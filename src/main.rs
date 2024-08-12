use std::error::Error;
use std::io;
use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::prelude::PermissionsExt,
    time::Duration,
};

use config::{Config, Service};
use tokio::task::JoinHandle;
use tokio::{net::UdpSocket, signal, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::debug;
use wireguard::Client;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

mod caddy;
mod config;
mod dns;
mod ipaddrstore;
mod keystore;
mod wireguard;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This application only supports linux!");
}

async fn run() -> Result<(), Box<dyn Error>> {
    let config_path = if let Some(arg) = std::env::args().nth(1) {
        arg
    } else {
        let Ok(env) = std::env::var("TUN_CONFIG") else {
            return Err("no config file: provide the path of the config file as an arument or with the TUN_CONFIG environment variable".into());
        };
        if env.is_empty() {
            return Err("no config file provided: TUN_CONFIG is empty".into());
        }
        env
    };

    let config = config::read(&config_path)?;
    let clients = load_clients(&config)?;
    let server_key = keystore::load(&config.wireguard.interface_name, &config.data_dir)?;

    let interface = wireguard::Interface::create(
        config.wireguard.interface_name.clone(),
        server_key,
        config.wireguard.listen_port,
        config.wireguard.ipv4,
        config.wireguard.ipv6,
        &clients,
    )
    .await?;

    generate_client_configs(&interface, &clients, &config)?;
    configure_caddy(&config, &clients).await?;
    let (dns_cancellation_token, dns_join_handle) = setup_dns(&config).await?;

    signal::ctrl_c().await?;
    dns_cancellation_token.cancel();
    interface.delete().await?;
    timeout(Duration::from_secs(1), dns_join_handle).await??;

    Ok(())
}

fn load_clients(config: &Config) -> Result<Vec<Client>, Box<dyn Error>> {
    let mut clients = Vec::new();

    for client_config in &config.clients {
        let key = keystore::load(&client_config.id, &config.data_dir)?;

        clients.push(Client {
            id: client_config.id.clone(),
            key,
            ipv4: None,
            ipv6: None,
            groups: client_config.groups.clone(),
        });
    }

    ipaddrstore::load(
        config.wireguard.ipv4,
        config.wireguard.ipv6,
        &config.data_dir,
        &mut clients,
    )?;

    debug!(?clients, "successfully loaded client data");

    Ok(clients)
}

fn generate_client_configs(
    interface: &wireguard::Interface,
    clients: &[Client],
    config: &Config,
) -> Result<(), io::Error> {
    let config_dir = config.data_dir.join("client_configs");
    fs::create_dir_all(&config_dir)?;

    for client in clients {
        let client_config =
            interface.generate_client_config(client, &config.wireguard.server_endpoint);

        let path = config_dir.join(format!("{}.conf", client.id));
        let mut file = fs::File::create(path)?;
        file.write_all(client_config.as_bytes())?;

        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
    }

    Ok(())
}

fn access_allowed(client: &Client, service: &Service) -> bool {
    let mut client_groups = client.groups.clone().unwrap_or_default();
    client_groups.push(client.id.clone());
    for group in &service.groups {
        if client.id == *group || client_groups.contains(group) {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_lines)]
async fn configure_caddy(config: &Config, clients: &[Client]) -> Result<(), Box<dyn Error>> {
    let mut routes = Vec::new();
    for service in &config.services {
        let mut allowed_ips = Vec::new();
        for client in clients {
            if access_allowed(client, service) {
                if let Some(ipv4) = client.ipv4 {
                    allowed_ips.push(IpAddr::V4(ipv4.address()));
                }
                if let Some(ipv6) = client.ipv6 {
                    allowed_ips.push(IpAddr::V6(ipv6.address()));
                }
            }
        }

        debug!(?allowed_ips, "adding route for service {}", service.hostname);

        routes.push(caddy::Route {
            matcher: Some(caddy::Match::And(vec![
                caddy::Match::Host(vec![service.hostname.clone()]),
                caddy::Match::ClientIp {
                    ranges: allowed_ips,
                },
            ])),
            handle: vec![caddy::Handler::ReverseProxy {
                upstreams: vec![caddy::Upstream {
                    dial: service.address.clone(),
                }],
                headers: Some(caddy::ReverseProxyHeaders {
                    request: Some(caddy::ReverseProxyHeadersRequest {
                        add: Some(HashMap::from([(
                            "Host".to_owned(),
                            vec!["{http.reverse_proxy.upstream.hostport}".to_owned()],
                        )])),
                        set: None,
                    }),
                }),
            }],
        });
    }

    routes.push(caddy::Route {
        matcher: None,
        handle: vec![caddy::Handler::StaticResponse {
            status_code: 404,
            body: "404 Not found".to_owned(),
        }],
    });

    let mut listen_addresses = Vec::with_capacity(2);
    if let Some(ipv4) = config.wireguard.ipv4 {
        listen_addresses.push(SocketAddr::V4(SocketAddrV4::new(
            ipv4.address(),
            config.http_listen_port,
        )));
    }
    if let Some(ipv6) = config.wireguard.ipv6 {
        listen_addresses.push(SocketAddr::V6(SocketAddrV6::new(
            ipv6.address(),
            config.http_listen_port,
            0,
            0,
        )));
    }

    let data = caddy::Config {
        apps: caddy::App::Http {
            http_port: None,
            https_port: None,
            servers: HashMap::from([(
                "test".to_owned(),
                caddy::HttpServer {
                    listen: listen_addresses,
                    routes,
                    automatic_https: Some(caddy::AutomaticHttps {
                        disable: true,
                        disable_redirects: false,
                        disable_certificates: false,
                        skip: None,
                        skip_certificates: None,
                    }),
                },
            )]),
        },
    };

    debug!(config = ?data, "configurating caddy");

    let res = reqwest::Client::new()
        .post(format!("{}/load", config.caddy.api_url.clone()))
        .json(&data)
        .send()
        .await?;

    if res.status() != 200 {
        return Err(format!(
            "Error while setting caddy configuration (status: {}): {}",
            res.status(),
            res.text().await?
        )
        .into());
    }

    Ok(())
}

async fn setup_dns(config: &Config) -> Result<(CancellationToken, JoinHandle<()>), Box<dyn Error>> {
    let dns = dns::Server::new();

    for service in &config.services {
        dns.set_dns_record(
            format!("{}.", service.hostname).parse()?,
            config.wireguard.ipv4.map(|v| v.address()),
            config.wireguard.ipv6.map(|v| v.address()),
        )
        .await;
    }

    let device_name = CString::new(config.wireguard.interface_name.to_string())?;
    let mut dns_listen_sockets = Vec::with_capacity(2);
    if let Some(ipv4) = config.wireguard.ipv4 {
        let socket = UdpSocket::bind((ipv4.address(), 53)).await.unwrap();

        socket.bind_device(Some(device_name.as_bytes_with_nul()))?;
        dns_listen_sockets.push(socket);
    }
    if let Some(ipv6) = config.wireguard.ipv6 {
        let socket = UdpSocket::bind((ipv6.address(), 53)).await.unwrap();
        socket.bind_device(Some(device_name.as_bytes_with_nul()))?;
        dns_listen_sockets.push(socket);
    }

    let cancellation_token = CancellationToken::new();
    let token = cancellation_token.clone();
    let join_handle = tokio::spawn(async move {
        dns.listen(dns_listen_sockets, token).await.unwrap();
    });

    Ok((cancellation_token, join_handle))
}
