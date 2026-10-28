//! Addresses (CLI_SPEC.md §2.4, API.md `GetCurrentAddress` / `NewAddress` /
//! `InspectAddress`): the key's current and fresh unified addresses through
//! upstream's address APIs, the network-independent parse behind
//! `address inspect`, and the `ext_gyges_address_labels` table behind
//! `address new --label` (DATA_MODEL.md §5.3).
//!
//! The receiver list is built the same way for all three, from the encoded
//! address, so `address current` and `address inspect` of the same string
//! always agree. The Orchard receiver is listed once, as Orchard: after NU6.3
//! the same receiver also takes Ironwood notes (`zcash_keys` "Ironwood
//! shares the Orchard receiver"), and a UA has no separate Ironwood item.

use rusqlite::{OptionalExtension as _, named_params};
use uuid::Uuid;
use zcash_address::unified::{self, Container as _};
use zcash_address::{ConversionError, ToAddress as _, TryFromAddress, ZcashAddress};
use zcash_client_backend::data_api::{
    Account as _, AddressSource, WalletRead as _, WalletWrite as _,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
use zcash_protocol::consensus::NetworkType;
use zip32::DiversifierIndex;

use crate::Pool;
use crate::ext::{ExtTable, with_ext};
use crate::registry::Wallet;
use crate::tx::{TxError, account_of, internal};

/// `address new` without `--receivers` (CLI_SPEC.md §2.4): shielded only,
/// so a fresh address never links to a transparent receiver.
pub const DEFAULT_RECEIVERS: [Pool; 2] = [Pool::Orchard, Pool::Sapling];

/// Longest label `address new --label` accepts, in bytes.
pub const MAX_LABEL_BYTES: usize = 128;

/// One receiver of an address (`gyges.v1.Receiver`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receiver {
    pub pool: Pool,
    /// The receiver re-encoded standalone (`zs1…`, `t1…`); empty for
    /// Orchard, which has no standalone encoding.
    pub encoded: String,
}

/// One of the key's own unified addresses (`gyges.v1.AddressInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressInfo {
    pub address: String,
    /// Decimal; a diversifier index is 88 bits.
    pub diversifier_index: String,
    pub receivers: Vec<Receiver>,
    pub label: Option<String>,
}

/// What kind of address a string encodes (`gyges.v1.AddressKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    Unified,
    Sapling,
    TransparentP2pkh,
    TransparentP2sh,
    /// ZIP 320: payable from transparent funds only.
    Tex,
}

/// A parsed address, on whatever network it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspected {
    pub network: NetworkType,
    pub kind: AddressKind,
    pub receivers: Vec<Receiver>,
}

impl Inspected {
    /// True for ZIP 320 addresses: a payment takes the two-step flow.
    pub fn transparent_source_only(&self) -> bool {
        self.kind == AddressKind::Tex
    }

    /// Whether the address is usable on `net`. Regtest transparent
    /// addresses are encoded with testnet's prefixes, so a testnet-encoded
    /// transparent address is also a regtest one.
    pub fn on_network(&self, net: NetworkType) -> bool {
        self.network == net
            || (net == NetworkType::Regtest
                && self.network == NetworkType::Test
                && matches!(
                    self.kind,
                    AddressKind::TransparentP2pkh | AddressKind::TransparentP2sh
                ))
    }
}

impl TryFromAddress for Inspected {
    type Error = std::convert::Infallible;

    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::single(
            net,
            AddressKind::Sapling,
            sapling_receiver(net, data),
        ))
    }

    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let receivers = data
            .items()
            .into_iter()
            .filter_map(|r| match r {
                unified::Receiver::Orchard(_) => Some(Receiver {
                    pool: Pool::Orchard,
                    encoded: String::new(),
                }),
                unified::Receiver::Sapling(d) => Some(sapling_receiver(net, d)),
                unified::Receiver::P2pkh(h) => Some(transparent_receiver(
                    ZcashAddress::from_transparent_p2pkh(net, h),
                )),
                unified::Receiver::P2sh(h) => Some(transparent_receiver(
                    ZcashAddress::from_transparent_p2sh(net, h),
                )),
                // Receiver types this release does not know are not listed.
                unified::Receiver::Unknown { .. } => None,
            })
            .collect();
        Ok(Self {
            network: net,
            kind: AddressKind::Unified,
            receivers,
        })
    }

    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::single(
            net,
            AddressKind::TransparentP2pkh,
            transparent_receiver(ZcashAddress::from_transparent_p2pkh(net, data)),
        ))
    }

    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::single(
            net,
            AddressKind::TransparentP2sh,
            transparent_receiver(ZcashAddress::from_transparent_p2sh(net, data)),
        ))
    }

    /// The receiver of a TEX address is the P2PKH hash it wraps.
    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::single(
            net,
            AddressKind::Tex,
            transparent_receiver(ZcashAddress::from_transparent_p2pkh(net, data)),
        ))
    }
}

impl Inspected {
    fn single(network: NetworkType, kind: AddressKind, receiver: Receiver) -> Self {
        Self {
            network,
            kind,
            receivers: vec![receiver],
        }
    }
}

fn transparent_receiver(addr: ZcashAddress) -> Receiver {
    Receiver {
        pool: Pool::Transparent,
        encoded: addr.encode(),
    }
}

fn sapling_receiver(net: NetworkType, data: [u8; 43]) -> Receiver {
    Receiver {
        pool: Pool::Sapling,
        encoded: ZcashAddress::from_sapling(net, data).encode(),
    }
}

/// Parse any Zcash address without assuming a network: checksum, encoding
/// and receivers. The error text is safe to print (it never quotes the
/// input).
pub fn inspect(s: &str) -> Result<Inspected, String> {
    let addr = ZcashAddress::try_from_encoded(s.trim()).map_err(|e| e.to_string())?;
    addr.convert::<Inspected>().map_err(|e| match e {
        ConversionError::Unsupported(u) => u.to_string(),
        other => other.to_string(),
    })
}

/// The upstream request for a receiver list: listed receivers required,
/// the others omitted. Ironwood names the Orchard receiver.
pub fn request_for(pools: &[Pool]) -> Result<UnifiedAddressRequest, TxError> {
    let pick = |yes: bool| {
        if yes {
            ReceiverRequirement::Require
        } else {
            ReceiverRequirement::Omit
        }
    };
    let orchard = pools.contains(&Pool::Orchard) || pools.contains(&Pool::Ironwood);
    let sapling = pools.contains(&Pool::Sapling);
    if !orchard && !sapling {
        return Err(TxError::InvalidArgument(
            "a unified address needs a shielded receiver: include orchard or sapling".into(),
        ));
    }
    UnifiedAddressRequest::custom(
        pick(orchard),
        pick(sapling),
        pick(pools.contains(&Pool::Transparent)),
    )
    .map_err(|e| TxError::InvalidArgument(format!("receiver list: {e:?}")))
}

/// Upstream address errors, mapped to what the client can act on.
fn address_error(context: &str, e: SqliteClientError) -> TxError {
    match e {
        SqliteClientError::ChainHeightUnknown => TxError::NotSynced(
            "the wallet does not know the chain tip yet; run `gyges sync wait` first".into(),
        ),
        SqliteClientError::ReachedGapLimit(..) => TxError::InvalidArgument(
            "every transparent receiver inside the gap limit has been handed out; \
             receive at one of them first, or leave transparent out"
                .into(),
        ),
        SqliteClientError::AddressGeneration(e) => {
            TxError::UnsupportedPool(format!("cannot derive the requested receivers: {e}"))
        }
        other => TxError::Internal(format!("{context}: {other}")),
    }
}

/// Decimal rendering of an 88-bit little-endian diversifier index.
pub fn diversifier_decimal(j: DiversifierIndex) -> String {
    let mut wide = [0u8; 16];
    wide[..11].copy_from_slice(j.as_bytes());
    u128::from_le_bytes(wide).to_string()
}

/// The key's current address: the one most recently handed out, by any
/// receiver set. On a fresh key that is the account's default address,
/// which upstream exposes with every receiver the key has when it creates
/// the account. A wallet without any exposed address (none that Gyges
/// creates) gets the default address of [`DEFAULT_RECEIVERS`], persisted
/// and marked exposed so that it stays current. Works before the first
/// sync.
pub fn current(wallet: &mut Wallet) -> Result<AddressInfo, TxError> {
    let account = account_of(wallet)?;
    let last = wallet
        .get_last_generated_address_matching(account, UnifiedAddressRequest::ALLOW_ALL)
        .map_err(|e| address_error("last generated address", e))?;
    let ua = match last {
        Some(ua) => ua,
        None => {
            let request = request_for(&DEFAULT_RECEIVERS)?;
            let acct = wallet
                .get_account(account)
                .map_err(|e| address_error("reading the account", e))?
                .ok_or_else(|| TxError::Internal("the wallet has no account".into()))?;
            let (_, j) = acct.uivk().default_address(request).map_err(|e| {
                TxError::UnsupportedPool(format!("cannot derive the default address: {e}"))
            })?;
            wallet
                .get_address_for_index(account, j, request)
                .map_err(|e| address_error("storing the default address", e))?
                .ok_or_else(|| {
                    TxError::Internal("the default diversifier index has no address".into())
                })?
        }
    };
    describe(wallet, account, &ua)
}

/// `address new`: a fresh diversified address with exactly `pools`'
/// receivers, optionally labelled.
pub fn new_address(
    wallet: &mut Wallet,
    pools: &[Pool],
    label: Option<&str>,
) -> Result<AddressInfo, TxError> {
    if let Some(l) = label {
        check_label(l)?;
    }
    let request = request_for(pools)?;
    let account = account_of(wallet)?;
    let (ua, _) = wallet
        .get_next_available_address(account, request)
        .map_err(|e| address_error("next available address", e))?
        .ok_or_else(|| TxError::Internal("the wallet has no account".into()))?;
    if let Some(l) = label {
        set_label(wallet, &ua.encode(wallet.params()), l)?;
    }
    describe(wallet, account, &ua)
}

fn check_label(label: &str) -> Result<(), TxError> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err(TxError::InvalidArgument(format!(
            "a label is 1 to {MAX_LABEL_BYTES} bytes without control characters"
        )));
    }
    Ok(())
}

/// `AddressInfo` for one of the account's addresses.
fn describe(
    wallet: &mut Wallet,
    account: zcash_client_sqlite::AccountUuid,
    ua: &UnifiedAddress,
) -> Result<AddressInfo, TxError> {
    let params = *wallet.params();
    let encoded = ua.encode(&params);
    let receivers = inspect(&encoded)
        .map_err(|e| internal("re-parsing an own address", e))?
        .receivers;
    let diversifier_index = wallet
        .list_addresses(account)
        .map_err(|e| address_error("listing addresses", e))?
        .into_iter()
        .find(|a| a.address().encode(&params) == encoded)
        .and_then(|a| match a.source() {
            AddressSource::Derived {
                diversifier_index, ..
            } => Some(diversifier_decimal(diversifier_index)),
            #[allow(unreachable_patterns)]
            _ => None,
        })
        .unwrap_or_default();
    let label = label_of(wallet, &encoded)?;
    Ok(AddressInfo {
        address: encoded,
        diversifier_index,
        receivers,
        label,
    })
}

// ---------------------------------------------------------------------------
// ext_gyges_address_labels
// ---------------------------------------------------------------------------

/// The external migration's id (random, fixed forever).
pub const LABELS_MIGRATION_ID: Uuid = Uuid::from_u128(0x2c6b_91d4_0f3e_4a7c_b85d_6e1a_93f2_07c8);

const LABELS: &str = "ext_gyges_address_labels";

/// Creates `ext_gyges_address_labels` (DATA_MODEL.md §5.3; the `ext_`
/// prefix is upstream's rule for application tables, as for §5.1).
pub const LABELS_MIGRATION: ExtTable = ExtTable {
    id: LABELS_MIGRATION_ID,
    table: LABELS,
    description: "Creates the Gyges address labels (ext_gyges_address_labels).",
    create: create_labels_migration,
};

fn create_labels_migration() -> String {
    format!(
        "CREATE TABLE {LABELS} (
            address     TEXT NOT NULL PRIMARY KEY,
            label       TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        );"
    )
}

fn set_label(wallet: &mut Wallet, address: &str, label: &str) -> Result<(), TxError> {
    let now = crate::profile::unix_now();
    with_ext(wallet, |ext| {
        ext.execute(
            &format!(
                "INSERT INTO {LABELS} (address, label, created_at) \
                     VALUES (:address, :label, :now) \
                     ON CONFLICT (address) DO UPDATE SET label = excluded.label"
            ),
            named_params! {":address": address, ":label": label, ":now": now},
        )
    })
    .map(|_| ())
    .map_err(|e: rusqlite::Error| internal("storing the label", e))
}

fn label_of(wallet: &mut Wallet, address: &str) -> Result<Option<String>, TxError> {
    with_ext(wallet, |ext| {
        ext.query_row(
            &format!("SELECT label FROM {LABELS} WHERE address = :address"),
            named_params! {":address": address},
            |r| r.get(0),
        )
        .optional()
    })
    .map_err(|e: rusqlite::Error| internal("reading the label", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use zcash_keys::address::Address;

    #[test]
    fn inspects_every_kind_on_its_own_network() {
        let p = Network::Regtest.consensus_params();
        let t = Address::Transparent(transparent::address::TransparentAddress::PublicKeyHash(
            [7; 20],
        ))
        .encode(&p);
        let i = inspect(&t).unwrap();
        // Regtest transparent addresses use testnet's prefixes.
        assert_eq!(i.network, NetworkType::Test);
        assert!(i.on_network(NetworkType::Regtest));
        assert!(i.on_network(NetworkType::Test));
        assert!(!i.on_network(NetworkType::Main));
        assert_eq!(i.kind, AddressKind::TransparentP2pkh);
        assert_eq!(
            i.receivers,
            vec![Receiver {
                pool: Pool::Transparent,
                encoded: t.clone()
            }]
        );
        assert!(!i.transparent_source_only());

        let tex = Address::Tex([7; 20]).encode(&p);
        let i = inspect(&tex).unwrap();
        assert_eq!(i.kind, AddressKind::Tex);
        assert!(i.transparent_source_only());
        assert_eq!(i.receivers[0].encoded, t, "the TEX hash as P2PKH");

        let main_t = Address::Transparent(transparent::address::TransparentAddress::PublicKeyHash(
            [7; 20],
        ))
        .encode(&Network::Mainnet.consensus_params());
        let mainnet = inspect(&main_t).unwrap();
        assert_eq!(mainnet.network, NetworkType::Main);
        assert!(!mainnet.on_network(NetworkType::Regtest));

        assert!(inspect("nonsense").is_err());
        // One flipped character breaks the checksum.
        let mut bad = t.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'a' { b'b' } else { b'a' };
        assert!(inspect(std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn receiver_requests_need_a_shielded_receiver() {
        assert!(request_for(&[Pool::Transparent]).is_err());
        assert!(request_for(&[]).is_err());
        let r = request_for(&[Pool::Ironwood, Pool::Transparent]).unwrap();
        let UnifiedAddressRequest::Custom(r) = r else {
            panic!("custom request")
        };
        assert_eq!(r.orchard(), ReceiverRequirement::Require);
        assert_eq!(r.sapling(), ReceiverRequirement::Omit);
        assert_eq!(r.p2pkh(), ReceiverRequirement::Require);
    }

    #[test]
    fn diversifier_indices_print_in_decimal() {
        assert_eq!(diversifier_decimal(DiversifierIndex::new()), "0");
        assert_eq!(diversifier_decimal(DiversifierIndex::from(300u32)), "300");
        let max = DiversifierIndex::from([0xff; 11]);
        assert_eq!(diversifier_decimal(max), ((1u128 << 88) - 1).to_string());
    }

    #[test]
    fn labels_are_short_printable_text() {
        assert!(check_label("savings").is_ok());
        assert!(check_label("").is_err());
        assert!(check_label("a\nb").is_err());
        assert!(check_label(&"x".repeat(MAX_LABEL_BYTES + 1)).is_err());
    }
}
