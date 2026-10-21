//! The three Zcash networks a daemon can serve (one daemon per network,
//! OVERVIEW.md Q-C2).

use std::fmt;
use std::str::FromStr;

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
    fn serde_uses_lowercase_names() {
        let s = toml::to_string(&Network::Regtest).unwrap_or_default();
        // A bare enum is not a TOML document; check through a wrapper.
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            network: Network,
        }
        let w: W = toml::from_str("network = \"testnet\"").unwrap();
        assert_eq!(w.network, Network::Testnet);
        assert_eq!(toml::to_string(&w).unwrap().trim(), "network = \"testnet\"");
        let _ = s;
    }
}
