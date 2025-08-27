use core::fmt;
use std::net::IpAddr;

use base64::DecodeError;
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use cidr::{Ipv4Inet, Ipv6Inet};
use netlink_packet_route::link::LinkLayerType;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
use netlink_packet_wireguard::constants::{AF_INET, AF_INET6};
use netlink_packet_wireguard::nlas::{WgAllowedIp, WgPeer};
use thiserror::Error;
use tracing::{debug, info, instrument, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::Id;

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeerAttrs},
    Wireguard, WireguardCmd,
};

/// Wireguard key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    private_key: x25519_dalek::StaticSecret,
    public_key: x25519_dalek::PublicKey,
}

#[derive(Debug, Error)]
pub enum InvalidKeyError {
    #[error("key length must be 32 bytes but was {0} bytes")]
    Length(usize),
    #[error("key is not base64 encoded: {0}")]
    Decode(#[from] DecodeError),
}

impl Key {
    /// Generate new random x25519 key
    pub fn generate_random() -> Self {
        let secret = x25519_dalek::StaticSecret::random();
        Self {
            public_key: x25519_dalek::PublicKey::from(&secret),
            private_key: secret,
        }
    }

    pub fn private_key_to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    pub fn public_key_to_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn from_base64(key: &str) -> Result<Self, InvalidKeyError> {
        let bytes = b64.decode(key)?;
        if bytes.len() != 32 {
            return Err(InvalidKeyError::Length(bytes.len()));
        }

        let bytes: [u8; 32] = bytes.try_into().unwrap();
        let secret = x25519_dalek::StaticSecret::from(bytes);

        Ok(Self {
            public_key: x25519_dalek::PublicKey::from(&secret),
            private_key: secret,
        })
    }

    pub fn private_key_base64(&self) -> String {
        b64.encode(self.private_key.to_bytes())
    }

    pub fn public_key_base64(&self) -> String {
        b64.encode(self.public_key.to_bytes())
    }
}

pub struct Client {
    pub id: Id,
    pub key: Key,
    pub ipv4: Option<Ipv4Inet>,
    pub ipv6: Option<Ipv6Inet>,
    pub groups: Option<Vec<Id>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("netlink error: {0}")]
    GenericNetlink(#[from] genetlink::GenetlinkError),
    #[error("netlink error: {0}")]
    RTNetlink(#[from] rtnetlink::Error),
    #[error("netlink decode error: {0}")]
    NetlinkDecode(#[from] netlink_packet_utils::DecodeError),
    #[error("wireguard interface {0} not found")]
    InterfaceNotFound(String),
}

pub struct Interface {
    // If interface_name is None the interface has been deleted
    name: Option<Id>,
    key: Key,
    listen_port: u16,
    ipv4: Option<Ipv4Inet>,
    ipv6: Option<Ipv6Inet>,
}

impl Interface {
    #[instrument(skip(interface_name, key, ipv4, ipv6, clients), fields(interface_name = %interface_name))]
    pub async fn create(
        interface_name: Id,
        key: Key,
        listen_port: u16,
        ipv4: Option<Ipv4Inet>,
        ipv6: Option<Ipv6Inet>,
        clients: &[Client],
    ) -> Result<Self, Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // Create wireguard interface
        debug!("creating link");
        let mut request = handle.link().add();
        request.message_mut().header.link_layer_type = LinkLayerType::Netrom;

        let mut nlas = vec![
            LinkAttribute::IfName(interface_name.to_string()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wireguard)]),
            // 1280 MTU is the minimum (for IPv6) and should be best for compatability
            // https://keremerkan.net/posts/wireguard-mtu-fixes/
            // 1420 seemingly caused packets to be dropped in some cases (especially android
            // clients)
            LinkAttribute::Mtu(1280),
        ];

        request.message_mut().attributes.append(&mut nlas);
        request.execute().await?;

        configure_interface(&interface_name, &key, listen_port, clients).await?;

        // Get wireguard interface
        let mut links = handle
            .link()
            .get()
            .match_name(interface_name.to_string())
            .execute();

        if let Some(link) = links.try_next().await? {
            // Add addresses to interface
            if let Some(ipv4) = ipv4 {
                debug!("adding ipv4 address {}", ipv4.address());
                handle
                    .address()
                    .add(
                        link.header.index,
                        IpAddr::V4(ipv4.address()),
                        ipv4.network_length(),
                    )
                    .execute()
                    .await?;
            }
            if let Some(ipv6) = ipv6 {
                debug!("adding ipv6 address {}", ipv6.address());
                handle
                    .address()
                    .add(
                        link.header.index,
                        IpAddr::V6(ipv6.address()),
                        ipv6.network_length(),
                    )
                    .execute()
                    .await?;
            }

            // Bring link up
            debug!("bringing up link");
            handle.link().set(link.header.index).up().execute().await?;
            info!("interface created");
        } else {
            return Err(Error::InterfaceNotFound(interface_name.to_string()));
        }

        Ok(Self {
            name: Some(interface_name),
            key,
            listen_port,
            ipv4,
            ipv6,
        })
    }

    /// Deletes the wireguard interface
    ///
    /// Should __always__ be called before dropping the wireguard interface.
    /// The drop implementation deletes the interface if it still exists but blocks the thread because drop
    /// implementations cannot be async. Additionally the drop implementation panics if an error
    /// occurs while the delete method allows for graceful handling of the error
    pub async fn delete(mut self) -> Result<(), Error> {
        if let Some(name) = self.name.take() {
            delete_link(name).await
        } else {
            Ok(())
        }
    }

    pub fn generate_client_config(&self, client: &Client, server_endpoint: &str) -> String {
        let mut ips = Vec::with_capacity(2);
        if let Some(ipv4) = client.ipv4 {
            ips.push(ipv4.to_string());
        }
        if let Some(ipv6) = client.ipv6 {
            ips.push(ipv6.to_string());
        }
        let address = ips.join(", ");

        let mut server_ips = Vec::with_capacity(2);
        if let Some(ip) = self.ipv4 {
            server_ips.push(ip.address().to_string());
        }
        if let Some(ip) = self.ipv6 {
            server_ips.push(ip.address().to_string());
        }
        let server_ips = server_ips.join(", ");

        let server_endpoint = format!("{}:{}", server_endpoint, self.listen_port);

        format!(
            "[Interface]\n\
            PrivateKey = {}\n\
            Address = {}\n\
            DNS = {}\n\
            \n\
            [Peer]\n\
            PublicKey = {}\n\
            Endpoint = {}\n\
            AllowedIps = {}",
            client.key.private_key_base64(),
            address,
            server_ips,
            self.key.public_key_base64(),
            server_endpoint,
            server_ips
        )
    }
}

async fn configure_interface(
    interface_name: &Id,
    key: &Key,
    listen_port: u16,
    clients: &[Client],
) -> Result<(), Error> {
    debug!("configuring interface to listen on port {}", listen_port);
    let (connection, mut handle, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let peers = clients
        .iter()
        .map(|c| {
            trace!(
                public_key = ?c.key.public_key_base64(),
                ipv4 = ?c.ipv4.map(|v| v.address()),
                ipv6 = ?c.ipv6.map(|v| v.address()),
                "adding peer"
            );

            let mut allowed_ips = Vec::new();
            if let Some(ipv4) = c.ipv4 {
                allowed_ips.push(WgAllowedIp(vec![
                    WgAllowedIpAttrs::Family(AF_INET),
                    WgAllowedIpAttrs::IpAddr(IpAddr::V4(ipv4.address())),
                    WgAllowedIpAttrs::Cidr(32),
                ]));
            }

            if let Some(ipv6) = c.ipv6 {
                allowed_ips.push(WgAllowedIp(vec![
                    WgAllowedIpAttrs::Family(AF_INET6),
                    WgAllowedIpAttrs::IpAddr(IpAddr::V6(ipv6.address())),
                    WgAllowedIpAttrs::Cidr(128),
                ]));
            }

            WgPeer(vec![
                WgPeerAttrs::PublicKey(c.key.public_key_to_bytes()),
                WgPeerAttrs::AllowedIps(allowed_ips),
            ])
        })
        .collect();

    let nlas = vec![
        WgDeviceAttrs::IfName(interface_name.to_string()),
        WgDeviceAttrs::ListenPort(listen_port),
        WgDeviceAttrs::Fwmark(listen_port.into()),
        WgDeviceAttrs::PrivateKey(key.private_key_to_bytes()),
        WgDeviceAttrs::Peers(peers),
    ];

    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas,
    });

    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut res = handle.request(nlmsg).await?;

    while let Some(result) = res.next().await {
        let rx_packet = result?;
        if let NetlinkPayload::Error(e) = rx_packet.payload {
            return Err(e.to_io().into());
        };
    }

    Ok(())
}

#[instrument(skip(interface_name), fields(interface_name = %interface_name))]
async fn delete_link(interface_name: Id) -> Result<(), Error> {
    trace!("deleting interface");
    let (rt_connection, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(rt_connection);

    // Get wireguard interface
    let mut links = rt_handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();

    if let Some(link) = links.try_next().await? {
        // Delete link
        rt_handle.link().del(link.header.index).execute().await?;
        debug!("interface {} deleted", interface_name);
    } else {
        return Err(Error::InterfaceNotFound(interface_name.to_string()));
    }

    Ok(())
}

impl Drop for Interface {
    fn drop(&mut self) {
        if let Some(name) = self.name.take() {
            // This blocks the thread and prevents other futures from running but no better way to
            // ensure the interface is deleted without async drop
            futures::executor::block_on(delete_link(name))
                .expect("error while deleting wireguard interface");
        }
    }
}
