//! The `gyges.v1.Gyges` service implementation.
//!
//! Only what ROADMAP.md has reached is implemented; every other RPC answers
//! `UNIMPLEMENTED` through the stubs `tonic-prost-build` generates.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gyges_core::{Config, Network};
use gyges_proto::v1::gyges_server::Gyges;
use gyges_proto::v1::{
    self, ApiVersion, FallbackStatus, FallbackTrust, GetInfoRequest, GetInfoResponse, NodeStatus,
    ShutdownRequest, ShutdownResponse, TorState, TorStatus,
};
use tokio::sync::Notify;
use tonic::{Request, Response, Status};

/// Everything the RPC handlers share.
#[derive(Debug)]
pub struct DaemonState {
    pub config: Config,
    pub network: Network,
    /// Unix seconds the daemon started.
    pub started_at: i64,
    /// Signalled by `Shutdown` (and by the signal handlers in `main`).
    pub shutdown: Notify,
}

impl DaemonState {
    pub fn new(config: Config, network: Network) -> Self {
        Self {
            config,
            network,
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
            // No ZakuraRpcBackend yet (ROADMAP.md M1): report "not connected"
            // honestly rather than omitting the field.
            node: Some(NodeStatus {
                connected: false,
                last_error: "node backend not implemented".to_string(),
                ..Default::default()
            }),
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
            keys: Vec::new(),
            default_key: self.config.default_key.clone(),
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

/// `gyges_core::Network` → wire enum.
pub fn proto_network(network: Network) -> v1::Network {
    match network {
        Network::Mainnet => v1::Network::Mainnet,
        Network::Testnet => v1::Network::Testnet,
        Network::Regtest => v1::Network::Regtest,
    }
}

fn unix_now() -> i64 {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_reports_version_network_and_config() {
        let cfg = Config {
            default_key: "main".into(),
            airgapped: true,
            ..Config::default()
        };
        let state = DaemonState::new(cfg, Network::Regtest);
        let info = state.info();
        assert_eq!(info.network, v1::Network::Regtest as i32);
        assert_eq!(info.api_version.unwrap().major, gyges_proto::API_MAJOR);
        assert_eq!(info.daemon_version, env!("CARGO_PKG_VERSION"));
        assert!(info.airgapped);
        assert_eq!(info.default_key, "main");
        assert_eq!(info.unlock_ttl_secs, 300);
        assert_eq!(info.default_min_confirmations, 10);
        assert!(!info.node.unwrap().connected);
        assert_eq!(info.tor.unwrap().state, TorState::Disabled as i32);
        assert!(info.started_at > 0);
    }
}
