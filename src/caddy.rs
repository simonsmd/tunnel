use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use serde::{
    ser::{SerializeMap, SerializeSeq, Serializer},
    Serialize,
};

#[derive(Serialize, Debug)]
pub struct Config {
    pub apps: Apps,
}

#[derive(Serialize, Debug)]
pub struct Apps {
    pub http: HttpApp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsApp>,
}

#[derive(Serialize, Debug)]
pub struct HttpApp {
    pub http_port: Option<u16>,
    pub https_port: Option<u16>,
    pub servers: HashMap<String, HttpServer>,
}

#[derive(Serialize, Debug)]
pub struct HttpServer {
    pub listen: Vec<SocketAddr>,
    pub routes: Vec<Route>,
    pub automatic_https: Option<AutomaticHttps>,
    pub tls_connection_policies: Option<Vec<TlsConnectionPolicy>>,
}

#[derive(Serialize, Debug)]
pub struct Route {
    #[serde(rename = "match", serialize_with = "serialize_match")]
    pub matcher: Option<Match>,
    pub handle: Vec<Handler>,
}

// always serialize match to array (as required by caddy config schema)
fn serialize_match<S>(matcher: &Option<Match>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(1))?;
    seq.serialize_element(matcher)?;
    seq.end()
}

#[derive(Serialize, Debug)]
#[allow(dead_code)]
pub enum Match {
    #[serde(rename = "client_ip")]
    ClientIp { ranges: Vec<IpAddr> },
    #[serde(rename = "remote_ip")]
    RemoteIp { ranges: Vec<IpAddr> },
    #[serde(rename = "host")]
    Host(Vec<String>),
    #[serde(untagged, serialize_with = "serialize_and_match")]
    And(Vec<Match>),
    #[serde(untagged)]
    Or(Vec<Match>),
}

fn serialize_and_match<S>(match_list: &Vec<Match>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(match_list.len()))?;
    for m in match_list {
        match m {
            Match::ClientIp { ranges } => {
                map.serialize_entry("client_ip", &HashMap::from([("ranges", ranges)]))?;
            }
            Match::RemoteIp { ranges } => {
                map.serialize_entry("remote_ip", &HashMap::from([("ranges", ranges)]))?;
            }
            Match::Host(hosts) => map.serialize_entry("host", &hosts)?,
            Match::And(_) => return Err(serde::ser::Error::custom("Cannot nest and match")),
            Match::Or(_) => {
                return Err(serde::ser::Error::custom(
                    "Cannot nest or match inside and match",
                ))
            }
        }
    }
    map.end()
}

#[derive(Serialize, Debug)]
#[serde(tag = "handler")]
pub enum Handler {
    #[serde(rename = "reverse_proxy")]
    ReverseProxy {
        upstreams: Vec<Upstream>,
        headers: Option<ReverseProxyHeaders>,
    },
    #[serde(rename = "static_response")]
    StaticResponse { status_code: u16, body: String },
}

#[derive(Serialize, Debug)]
pub struct Upstream {
    pub dial: String,
}

#[derive(Serialize, Debug)]
pub struct ReverseProxyHeaders {
    pub request: Option<ReverseProxyHeadersRequest>,
}

#[derive(Serialize, Debug)]
pub struct ReverseProxyHeadersRequest {
    pub add: Option<HashMap<String, Vec<String>>>,
    pub set: Option<HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Debug)]
pub struct TlsConnectionPolicy {}

#[derive(Serialize, Debug)]
pub struct AutomaticHttps {
    pub disable: bool,
    pub disable_redirects: bool,
    pub disable_certificates: bool,
    pub skip: Option<Vec<String>>,
    pub skip_certificates: Option<Vec<String>>,
}

#[derive(Serialize, Debug)]
pub struct TlsApp {
    pub certificates: TlsCertificates,
}

#[derive(Serialize, Debug)]
pub struct TlsCertificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_files: Option<Vec<TlsCertificateFile>>,
}

#[derive(Serialize, Debug)]
pub struct TlsCertificateFile {
    pub certificate: PathBuf,
    pub key: PathBuf,
}
