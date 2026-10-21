//! The `gyges.v1.Gyges` service implementation.
//!
//! Only what ROADMAP.md has reached is implemented; every other RPC answers
//! `UNIMPLEMENTED` through the stubs `tonic-prost-build` generates.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gyges_chain::{BlockDb, ChainBackend};
use gyges_core::{Config, KeyRegistry, Network, VaultManager};
use gyges_proto::v1::gyges_server::Gyges;
use gyges_proto::v1::{
    self, ApiVersion, ExportSeedRequest, ExportSeedResponse, ExportUfvkRequest, ExportUfvkResponse,
    FallbackStatus, FallbackTrust, GetInfoRequest, GetInfoResponse, InitKeyRequest,
    InitKeyResponse, ListKeysRequest, ListKeysResponse, LockKeyRequest, LockKeyResponse,
    NodeStatus, RestoreKeyRequest, RestoreKeyResponse, ShutdownRequest, ShutdownResponse, TorState,
    TorStatus, UnlockKeyRequest, UnlockKeyResponse,
};
use tokio::sync::Notify;
use tonic::{Request, Response, Status};

use crate::keys;

/// Everything the RPC handlers share.
#[derive(Debug)]
pub struct DaemonState {
    pub config: Config,
    pub network: Network,
    pub registry: KeyRegistry,
    /// Shared with every [`crate::Conn`], which drops its unlocks on close.
    pub vault: Arc<VaultManager>,
    /// `None` only when air-gapped.
    pub chain: Option<Arc<dyn ChainBackend>>,
    /// The shared compact block cache (`cache/blocks.sqlite`); `None` only
    /// when air-gapped.
    pub block_cache: Option<Arc<BlockDb>>,
    /// Unix seconds the daemon started.
    pub started_at: i64,
    /// Signalled by `Shutdown` (and by the signal handlers in `main`).
    pub shutdown: Notify,
}

impl DaemonState {
    pub fn new(
        config: Config,
        network: Network,
        registry: KeyRegistry,
        vault: VaultManager,
        chain: Option<Arc<dyn ChainBackend>>,
        block_cache: Option<Arc<BlockDb>>,
    ) -> Self {
        Self {
            config,
            network,
            registry,
            vault: Arc::new(vault),
            chain,
            block_cache,
            started_at: unix_now(),
            shutdown: Notify::new(),
        }
    }

    /// Build the `GetInfo` response from the current state.
    pub fn info(&self) -> GetInfoResponse {
        let fb = &self.config.fallback_lightwalletd;
        GetInfoResponse {
            network: proto_network(self.network) as i32,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: Some(ApiVersion {
                major: gyges_proto::API_MAJOR,
                minor: gyges_proto::API_MINOR,
            }),
            airgapped: self.config.airgapped,
            node: Some(self.node_status()),
            tor: Some(TorStatus {
                state: TorState::Disabled as i32,
                ..Default::default()
            }),
            fallback: Some(FallbackStatus {
                enabled: fb.enabled && !self.config.airgapped,
                grpc_url: fb.grpc_url.clone(),
                use_tor: fb.use_tor,
                trust: if fb.enabled {
                    FallbackTrust::Untested as i32
                } else {
                    FallbackTrust::Unspecified as i32
                },
            }),
            keys: keys::summaries(self),
            default_key: self.registry.default_key(),
            started_at: self.started_at,
            unlock_ttl_secs: self
                .config
                .vault
                .unlock_ttl
                .as_secs()
                .try_into()
                .unwrap_or(u32::MAX),
            default_min_confirmations: self.config.policy.min_confirmations,
        }
    }
}

impl DaemonState {
    /// `GetInfo.node` from the backend's last poll (API.md `NodeStatus`).
    /// Air-gapped: not connected, with the reason.
    pub fn node_status(&self) -> NodeStatus {
        let Some(chain) = &self.chain else {
            return NodeStatus {
                connected: false,
                last_error: "air-gapped: no node interface".to_string(),
                ..Default::default()
            };
        };
        let st = chain.status();
        let bounds = st.bounds.as_ref();
        NodeStatus {
            connected: st.connected,
            tip_height: bounds.map_or(0, |b| u32::from(b.tip_height)),
            tip_hash: bounds.map_or_else(String::new, |b| gyges_chain::display_hash(&b.tip_hash)),
            retained_from: bounds.map_or(0, |b| u32::from(b.retained_from)),
            pruned: st.pruned,
            // Zakura does not expose its `tx_retention` setting over RPC.
            tx_retention: 0,
            indexer_stream: false,
            last_error: if st.connected {
                String::new()
            } else if st.last_polled.is_none() {
                "not polled yet".to_string()
            } else {
                st.last_error
            },
            // No RPC in the set Gyges uses reports the node's version yet.
            node_version: String::new(),
        }
    }
}

/// `gyges_core::Network` → wire enum.
pub fn proto_network(network: Network) -> v1::Network {
    match network {
        Network::Mainnet => v1::Network::Mainnet,
        Network::Testnet => v1::Network::Testnet,
        Network::Regtest => v1::Network::Regtest,
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The tonic service; cheap to clone.
#[derive(Clone, Debug)]
pub struct GygesService {
    state: Arc<DaemonState>,
}

impl GygesService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Gyges for GygesService {
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        Ok(Response::new(self.state.info()))
    }

    async fn shutdown(
        &self,
        request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        // There is nothing in flight to drain yet (no proving, no TexQueue),
        // so graceful and forced shutdown currently behave the same.
        tracing::info!(
            graceful = request.get_ref().graceful,
            "shutdown requested over RPC"
        );
        self.state.shutdown.notify_one();
        Ok(Response::new(ShutdownResponse {}))
    }

    async fn list_keys(
        &self,
        _request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        Ok(Response::new(ListKeysResponse {
            keys: keys::summaries(&self.state),
        }))
    }

    async fn init_key(
        &self,
        request: Request<InitKeyRequest>,
    ) -> Result<Response<InitKeyResponse>, Status> {
        keys::init_key(self.state.clone(), request.into_inner())
            .await
            .map(Response::new)
    }

    async fn restore_key(
        &self,
        request: Request<RestoreKeyRequest>,
    ) -> Result<Response<RestoreKeyResponse>, Status> {
        keys::restore_key(self.state.clone(), request.into_inner())
            .await
            .map(Response::new)
    }

    async fn unlock_key(
        &self,
        request: Request<UnlockKeyRequest>,
    ) -> Result<Response<UnlockKeyResponse>, Status> {
        let conn = crate::conn::of_request(&request);
        keys::unlock_key(self.state.clone(), conn, request.into_inner())
            .await
            .map(Response::new)
    }

    async fn lock_key(
        &self,
        request: Request<LockKeyRequest>,
    ) -> Result<Response<LockKeyResponse>, Status> {
        keys::lock_key(&self.state, request.into_inner()).map(Response::new)
    }

    async fn export_ufvk(
        &self,
        request: Request<ExportUfvkRequest>,
    ) -> Result<Response<ExportUfvkResponse>, Status> {
        let conn = crate::conn::of_request(&request);
        keys::export_ufvk(&self.state, conn, request.into_inner()).map(Response::new)
    }

    async fn export_seed(
        &self,
        request: Request<ExportSeedRequest>,
    ) -> Result<Response<ExportSeedResponse>, Status> {
        keys::export_seed(self.state.clone(), request.into_inner())
            .await
            .map(Response::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_core::{Home, perms};

    #[test]
    fn info_reports_version_network_and_config() {
        let dir = tempfile::tempdir().unwrap();
        perms::set_mode(dir.path(), 0o700).unwrap();
        let cfg = Config {
            default_key: "main".into(),
            airgapped: true,
            ..Config::default()
        };
        let registry = KeyRegistry::open(Home::new(dir.path()), Network::Regtest, &cfg).unwrap();
        let vault = VaultManager::new(&cfg.vault);
        let state = DaemonState::new(cfg, Network::Regtest, registry, vault, None, None);
        let info = state.info();
        assert_eq!(info.network, v1::Network::Regtest as i32);
        assert_eq!(info.api_version.unwrap().major, gyges_proto::API_MAJOR);
        assert_eq!(info.daemon_version, env!("CARGO_PKG_VERSION"));
        assert!(info.airgapped);
        assert_eq!(info.default_key, "main");
        assert!(info.keys.is_empty());
        assert_eq!(info.unlock_ttl_secs, 300);
        assert_eq!(info.default_min_confirmations, 10);
        let node = info.node.unwrap();
        assert!(!node.connected);
        assert!(
            node.last_error.contains("air-gapped"),
            "{}",
            node.last_error
        );
        assert_eq!(info.tor.unwrap().state, TorState::Disabled as i32);
        assert!(info.started_at > 0);
    }
}
