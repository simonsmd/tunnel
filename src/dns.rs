use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolveHosts, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::{
        op::ResponseCode,
        rr::{LowerName, RData, RecordSet, RecordType},
    },
    Name,
};
use hickory_server::{
    authority::{
        AuthorityObject, Catalog, LookupControlFlow, LookupObject, LookupOptions, LookupRecords,
        MessageRequest, UpdateResult, ZoneType,
    },
    proto::ProtoError,
    server::RequestInfo,
    store::forwarder::{ForwardAuthority, ForwardConfig},
    ServerFuture,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

type RecordMap = HashMap<Name, (Option<Ipv4Addr>, Option<Ipv6Addr>)>;

/// DNS authority that stores tunnel-specific A and AAAA records and forwards all other lookups to
/// another authority
struct TunnelAuthority {
    records: Arc<RwLock<RecordMap>>,
    forward_authority: Box<dyn AuthorityObject>,
}

impl TunnelAuthority {
    pub fn new(forward_authority: Box<dyn AuthorityObject>) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            forward_authority,
        }
    }

    pub async fn set_records(&self, name: Name, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        debug!(?ipv4, ?ipv6, "setting record for {}", name);
        self.records.write().await.insert(name, (ipv4, ipv6));
    }

    async fn inner_lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Box<dyn LookupObject>> {
        if let Some((ipv4, ipv6)) = self.records.read().await.get(&name.clone().into()) {
            if query_type == RecordType::A {
                if let Some(ip) = ipv4 {
                    trace!("found tunnel local A record for {}: {}", name, ip);
                    let mut records = RecordSet::new(name.clone().into(), RecordType::A, 0);
                    records.add_rdata(RData::A((*ip).into()));
                    return Some(Box::new(LookupRecords::new(
                        lookup_options,
                        Arc::new(records),
                    )));
                }
            }

            if query_type == RecordType::AAAA {
                if let Some(ip) = ipv6 {
                    trace!("found tunnel local AAAA record for {}: {}", name, ip);
                    let mut records = RecordSet::new(name.clone().into(), RecordType::AAAA, 0);
                    records.add_rdata(RData::AAAA((*ip).into()));
                    return Some(Box::new(LookupRecords::new(
                        lookup_options,
                        Arc::new(records),
                    )));
                }
            }
        }

        trace!("no tunnel local record found for {}", name);
        None
    }
}

#[async_trait]
impl AuthorityObject for TunnelAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        static ROOT_ORIGIN: OnceLock<LowerName> = OnceLock::new();
        ROOT_ORIGIN.get_or_init(|| LowerName::from_str(".").unwrap())
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        if let Some(lo) = self.inner_lookup(name, rtype, lookup_options).await {
            return LookupControlFlow::Break(Ok(lo));
        }

        self.forward_authority
            .lookup(name, rtype, lookup_options)
            .await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        if let Some(lo) = self
            .inner_lookup(
                request_info.query.name(),
                request_info.query.query_type(),
                lookup_options,
            )
            .await
        {
            return LookupControlFlow::Break(Ok(lo));
        }

        self.forward_authority
            .search(request_info, lookup_options)
            .await
    }

    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        if let Some(lo) = self.inner_lookup(name, rtype, lookup_options).await {
            return LookupControlFlow::Break(Ok(lo));
        }

        self.forward_authority
            .consult(name, rtype, lookup_options, last_result)
            .await
    }

    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.forward_authority
            .get_nsec_records(name, lookup_options)
            .await
    }

    fn can_validate_dnssec(&self) -> bool {
        false
    }
}

pub struct Server {
    authority: Arc<TunnelAuthority>,
}

impl Server {
    pub fn new() -> Self {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.use_hosts_file = ResolveHosts::Never;

        // TODO: configurable upstream dns
        let forward_config = ForwardConfig {
            name_servers: NameServerConfigGroup::from_ips_tls(
                &[
                    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
                ],
                853,
                "dns.quad9.net".to_string(),
                true,
            ),
            options: Some(resolver_opts),
        };

        // Name::from_str(".").unwrap(),
        // ZoneType::External,
        let forward_authority = ForwardAuthority::builder_with_config(
            forward_config,
            TokioConnectionProvider::default(),
        )
        .build()
        .unwrap();

        let tunnel_authority = TunnelAuthority::new(Box::new(forward_authority));

        Self {
            authority: Arc::new(tunnel_authority),
        }
    }

    pub async fn set_dns_record(&self, name: Name, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        self.authority.set_records(name, ipv4, ipv6).await;
    }

    pub async fn listen(
        &self,
        sockets: Vec<UdpSocket>,
        cancellation_token: CancellationToken,
    ) -> Result<(), ProtoError> {
        info!("starting dns server");
        let mut catalog = Catalog::new();
        catalog.upsert(
            LowerName::from_str(".").unwrap(),
            vec![self.authority.clone()],
        );
        let mut server = ServerFuture::new(catalog);

        debug!("dns server listening on {:?}", sockets);
        for socket in sockets {
            server.register_socket(socket);
        }

        cancellation_token.cancelled().await;
        info!("dns server shutting down");
        server.shutdown_gracefully().await
    }
}
