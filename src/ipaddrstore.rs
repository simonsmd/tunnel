use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::Path,
};

use cidr::{IpCidr, Ipv4Inet, Ipv6Inet};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

use crate::{config::Id, wireguard::Client};

#[derive(Debug, Serialize, Deserialize)]
pub struct IpAddrPair {
    pub ipv4: Option<Ipv4Inet>,
    pub ipv6: Option<Ipv6Inet>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("not enough ip addresses in subnet {0}")]
    SubnetExhausted(IpCidr),
    #[error("invalid ip address store format: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("cannot read ip address store file: {0}")]
    IO(#[from] std::io::Error),
}

pub fn load(
    server_ipv4: Option<Ipv4Inet>,
    server_ipv6: Option<Ipv6Inet>,
    data_directory: &Path,
    clients: &mut Vec<Client>,
) -> Result<(), Error> {
    if !data_directory.exists() {
        fs::create_dir_all(data_directory)?;
    }

    let path = data_directory.join("ipaddrstore.yaml");
    let mut mapping: HashMap<Id, IpAddrPair> = if path.exists() {
        let data = fs::read_to_string(&path)?;
        serde_yaml::from_str(&data)?
    } else {
        debug!("no existing ip address mapping");
        HashMap::new()
    };

    let mut unavailable_ipv4: HashSet<Ipv4Inet> = mapping.values().filter_map(|p| p.ipv4).collect();
    let mut unavailable_ipv6: HashSet<Ipv6Inet> = mapping.values().filter_map(|p| p.ipv6).collect();

    if let Some(ip) = server_ipv4 {
        unavailable_ipv4.insert(ip.first());
        unavailable_ipv4.insert(ip.last());
        unavailable_ipv4.insert(ip);
    }

    if let Some(ip) = server_ipv6 {
        unavailable_ipv6.insert(ip.first());
        unavailable_ipv6.insert(ip.last());
        unavailable_ipv6.insert(ip);
    }

    for client in clients {
        let ipaddr_pair = mapping.get(&client.id).unwrap_or(&IpAddrPair {
            ipv4: None,
            ipv6: None,
        });

        if let Some(ip) = server_ipv4 {
            let cidr = ip.network();
            if ipaddr_pair.ipv4.is_none()
                || ipaddr_pair
                    .ipv4
                    .is_some_and(|a| !cidr.contains(&a.address()))
            {
                let ipaddr = cidr.iter().find(|a| !unavailable_ipv4.contains(a));
                if let Some(ipaddr) = ipaddr {
                    debug!("assigning ip {} to {}", ipaddr, client.id);
                    client.ipv4 = Some(ipaddr);
                    unavailable_ipv4.insert(ipaddr);
                } else {
                    return Err(Error::SubnetExhausted(IpCidr::V4(cidr)));
                }
            } else {
                client.ipv4 = ipaddr_pair.ipv4;
            }
        }

        if let Some(ip) = server_ipv6 {
            let cidr = ip.network();
            if ipaddr_pair.ipv6.is_none()
                || ipaddr_pair
                    .ipv6
                    .is_some_and(|a| !cidr.contains(&a.address()))
            {
                let ipaddr = cidr.iter().find(|a| !unavailable_ipv6.contains(a));
                if let Some(ipaddr) = ipaddr {
                    debug!("assigning ip {} to {}", ipaddr, client.id);
                    client.ipv6 = Some(ipaddr);
                    unavailable_ipv6.insert(ipaddr);
                } else {
                    return Err(Error::SubnetExhausted(IpCidr::V6(cidr)));
                }
            }
        } else {
            client.ipv6 = ipaddr_pair.ipv6;
        }

        mapping.insert(
            client.id.clone(),
            IpAddrPair {
                ipv4: client.ipv4,
                ipv6: client.ipv6,
            },
        );
    }

    let data = serde_yaml::to_string(&mapping)?;
    fs::File::create(&path)?.write_all(data.as_bytes())?;

    Ok(())
}
