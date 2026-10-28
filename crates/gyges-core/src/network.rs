//! The three Zcash networks a daemon can serve (one daemon per network,
//! OVERVIEW.md Q-C2).

use std::fmt;
use std::str::FromStr;

use zcash_protocol::consensus::{
    BlockHeight, MAIN_NETWORK, NetworkType, NetworkUpgrade, Parameters, TEST_NETWORK,
};
use zcash_protocol::local_consensus::LocalNetwork;

/// Which chain a `gygesd` instance serves; selects `$GYGES_HOME/<network>/`.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    /// Every network, in the order the docs list them.
    pub const ALL: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

    /// The CLI flag value and the directory name under `GYGES_HOME`.
    pub const fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }

    /// Sapling activation height, the default restore birthday (CLI_SPEC.md
    /// `key restore`).
    pub const fn sapling_activation_height(self) -> u32 {
        match self {
            Network::Mainnet => 419_200,
            Network::Testnet => 280_000,
            Network::Regtest => 1,
        }
    }

    /// NU5 activation height, the default Keystone import birthday
    /// (CLI_SPEC.md `key import-keystone`).
    pub const fn nu5_activation_height(self) -> u32 {
        match self {
            Network::Mainnet => 1_687_104,
            Network::Testnet => 1_842_420,
            Network::Regtest => 1,
        }
    }

    /// The consensus parameters `zcash_keys` and `zcash_client_sqlite` need
    /// (address encodings, coin type, activation heights).
    pub const fn consensus_params(self) -> ConsensusParams {
        match self {
            Network::Mainnet => ConsensusParams::Main,
            Network::Testnet => ConsensusParams::Test,
            Network::Regtest => ConsensusParams::Regtest,
        }
    }
}

/// `zcash_protocol::consensus::Parameters` for the three networks.
///
/// Mainnet and testnet are the upstream constants. Regtest activates every
/// network upgrade at height 1, which is what the Zebra-derived `zakurad`
/// does by default; the activation heights a regtest node actually reports
/// (`getblockchaininfo.upgrades`) are checked against this table when the
/// node backend connects (ROADMAP.md M1, **needs verification** against a
/// running `zakurad`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusParams {
    Main,
    Test,
    Regtest,
}

const REGTEST_ACTIVATION: BlockHeight = BlockHeight::from_u32(1);

/// Every upgrade active from height 1.
const REGTEST: LocalNetwork = LocalNetwork {
    overwinter: Some(REGTEST_ACTIVATION),
    sapling: Some(REGTEST_ACTIVATION),
    blossom: Some(REGTEST_ACTIVATION),
    heartwood: Some(REGTEST_ACTIVATION),
    canopy: Some(REGTEST_ACTIVATION),
    nu5: Some(REGTEST_ACTIVATION),
    nu6: Some(REGTEST_ACTIVATION),
    nu6_1: Some(REGTEST_ACTIVATION),
    nu6_2: Some(REGTEST_ACTIVATION),
    nu6_3: Some(REGTEST_ACTIVATION),
    nu7: None,
};

impl Parameters for ConsensusParams {
    fn network_type(&self) -> NetworkType {
        match self {
            ConsensusParams::Main => NetworkType::Main,
            ConsensusParams::Test => NetworkType::Test,
            ConsensusParams::Regtest => NetworkType::Regtest,
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            ConsensusParams::Main => MAIN_NETWORK.activation_height(nu),
            ConsensusParams::Test => TEST_NETWORK.activation_height(nu),
            ConsensusParams::Regtest => REGTEST.activation_height(nu),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error for an unrecognised network name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown network `{0}`; expected mainnet, testnet or regtest")]
pub struct UnknownNetwork(pub String);

impl FromStr for Network {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Network::ALL
            .into_iter()
            .find(|n| n.name() == s)
            .ok_or_else(|| UnknownNetwork(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for n in Network::ALL {
            assert_eq!(n.name().parse::<Network>(), Ok(n));
            assert_eq!(n.to_string(), n.name());
        }
        assert!("Mainnet".parse::<Network>().is_err());
    }

    #[test]
    fn activation_constants_agree_with_the_consensus_parameters() {
        for n in Network::ALL {
            let p = n.consensus_params();
            assert_eq!(
                p.activation_height(NetworkUpgrade::Sapling),
                Some(BlockHeight::from_u32(n.sapling_activation_height())),
                "{n}"
            );
            assert_eq!(
                p.activation_height(NetworkUpgrade::Nu5),
                Some(BlockHeight::from_u32(n.nu5_activation_height())),
                "{n}"
            );
        }
        assert_eq!(
            Network::Regtest.consensus_params().network_type(),
            NetworkType::Regtest
        );
    }

    #[test]
    fn serde_uses_lowercase_names() {
        // A bare enum is not a TOML document; check through a wrapper.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            network: Network,
        }
        let w: W = toml::from_str("network = \"testnet\"").unwrap();
        assert_eq!(w.network, Network::Testnet);
        assert_eq!(toml::to_string(&w).unwrap().trim(), "network = \"testnet\"");
    }
}
