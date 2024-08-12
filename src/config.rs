use core::fmt;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use config::{Config as ConfigB, ConfigError};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Id(String);

#[derive(Debug, Error)]
pub enum InvalidIdError {
    #[error("id {0} contains illegal characters (only alphanumeric characters and underscore are allowed)")]
    IllegalCharacters(String),
    #[error("id {0} starts or ends with underscore")]
    IllegalUnderscore(String),
    #[error("id is empty")]
    Empty,
}

impl Id {
    pub fn new(id: String) -> Result<Self, InvalidIdError> {
        if id.is_empty() {
            return Err(InvalidIdError::Empty);
        }
        for char in id.chars() {
            if !(char == '_' || char.is_ascii_alphanumeric()) {
                return Err(InvalidIdError::IllegalCharacters(id));
            }
        }
        if id.starts_with('_') || id.ends_with('_') {
            return Err(InvalidIdError::IllegalUnderscore(id));
        }
        Ok(Self(id))
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id = String::deserialize(deserializer)?;
        Id::new(id).map_err(serde::de::Error::custom)
    }
}

impl AsRef<Path> for Id {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub wireguard: Wireguard,
    pub caddy: Caddy,
    pub clients: Vec<Client>,
    pub http_listen_port: u16,
    pub services: Vec<Service>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wireguard {
    pub interface_name: Id,
    pub listen_port: u16,
    pub server_endpoint: String,
    pub ipv4: Option<cidr::Ipv4Inet>,
    pub ipv6: Option<cidr::Ipv6Inet>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Caddy {
    pub api_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Client {
    pub id: Id,
    pub groups: Option<Vec<Id>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    pub hostname: String,
    pub address: String,
    pub groups: Vec<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceHttps {
    pub redirect_http: bool,
    pub certificate: Option<Certificate>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Certificate {
    Auto,
    Selfsigned {
        path: PathBuf,
    },
    LetsEncrypt {
        email: String,
        // TODO: complete
    },
}

pub fn read(path: &str) -> Result<Config, ConfigError> {
    let Some(data_dir) = dirs::data_dir() else {
        return Err(ConfigError::Message(
            "Unable to find default data path. Please set data_dir in the config file".into(),
        ));
    };

    let config: Config = ConfigB::builder()
        .add_source(config::File::with_name(path))
        .add_source(config::Environment::with_prefix("TUN"))
        .set_default(
            "data_dir",
            data_dir
                .join("tunnel")
                .into_os_string()
                .into_string()
                .unwrap(),
        )?
        .set_default("http_listen_port", 80)?
        .set_default("caddy.api_url", "http://localhost:2019")?
        .build()?
        .try_deserialize()?;

    let client_ids: HashSet<Id> = config.clients.iter().map(|c| c.id.clone()).collect();

    if config.clients.is_empty() {
        warn!("no clients configured");
    }

    for client in &config.clients {
        // client id must not be equal to interface name because of keystore
        if client.id == config.wireguard.interface_name {
            return Err(ConfigError::Message(String::from(
                "client id must not be equal to interface name",
            )));
        }
        // no groyp with same id as a client
        if let Some(groups) = &client.groups {
            for group in groups {
                if client_ids.contains(group) {
                    return Err(ConfigError::Message(String::from(
                        "group id cannot be a client id",
                    )));
                }
            }
        }
    }

    if config.wireguard.ipv4.is_none() && config.wireguard.ipv6.is_none() {
        return Err(ConfigError::Message(String::from(
            "no ip address configured for wireguard interface",
        )));
    }

    if config.services.is_empty() {
        warn!("no services configured");
    }

    debug!(?config, "successfully read configuration");

    Ok(config)
}
