use std::{io, str::FromStr};
use crate::bridge::{BridgeStation};
use crate::common::{convert_HostAddress_to_HostAddr, HostAddress, Hostname};
use crate::configuration::{OutboundAction, OutboundClientProtocol, TransformerAction};
use crate::stations::modifiers::tls_packer::{TlsRepackerStation, TlsUnpackerStation};
use crate::stations::client::http_client::HttpTunnelProtocolClientStation;


pub struct RemoteLinkGuide {
    pub stream_address: HostAddress,
    pub stations: Vec<Box<dyn BridgeStation>>,
    pub client_station_index: Option<usize>,
}


pub fn get_default_remote_link(target: HostAddress) -> RemoteLinkGuide {
    let modifier_stations = get_modifier_stations(&target).unwrap();
    let (client_protocol_stations, server_address) = get_client_protocol_link(&target).unwrap();

    let mut sum_stations = Vec::new();
    sum_stations.extend(modifier_stations);
    sum_stations.extend(client_protocol_stations);

    RemoteLinkGuide {
        stream_address: server_address.unwrap_or(target),
        stations: sum_stations,
        client_station_index: None,
    }
}


fn get_modifier_stations(host: &HostAddress) -> io::Result<Vec<Box<dyn BridgeStation>>> {
    let global_config = crate::global::get_global_config();
    let transformer_config = global_config.get_transformer_action_by_host(
        &convert_HostAddress_to_HostAddr(host));

    let mut all_stations: Vec<Box<dyn BridgeStation>> = vec![];

    match transformer_config {
        Some(TransformerAction::SniTransformer(s)) => {
            let sni_name = match s.as_str() {
                "_" => None,
                "*" => Some(host.0.clone()),
                h => {
                    if let Ok(x) = Hostname::from_str(h) {
                        Some(x)
                    } else {
                        wd_log::log_warn_ln!("Invalid hostname {}", h);
                        Some(host.0.clone())
                    }
                }
            };
            wd_log::log_info_ln!("Use transformer: SNI Rewriter \"{}\"",
                if let Some(ref v) = sni_name { v.to_string() } else { "<omitted>".to_string() });

            let unpack_station = TlsUnpackerStation::new(host.0.clone(), sni_name.clone());
            let repack_station = TlsRepackerStation::new(host.0.clone(), sni_name.clone());

            all_stations.extend(vec![
                Box::new(unpack_station) as Box<dyn BridgeStation>,
                Box::new(repack_station),
            ]);
        }
        Some(TransformerAction::DirectTransformer) | None => {
            wd_log::log_info_ln!("Use transformer: Direct");
        }
    };

    Ok(all_stations)
}


pub fn get_client_protocol_link(target: &HostAddress)
    -> io::Result<(Vec<Box<dyn BridgeStation>>, Option<HostAddress>)> {
    let global_config = crate::global::get_global_config();
    let mut t = convert_HostAddress_to_HostAddr(target);
    t.1 = 0;
    let outbound_config = global_config.get_outbound_action_by_host(
        &t
    ); // TODO

    println!("get_client_protocol_link || target: {:?}, outbound_config: {:?}", target, outbound_config);

    let (protocol_stations, server_address): (Vec<Box<dyn BridgeStation>>, Option<HostAddress>) =
        match outbound_config {
            Some(OutboundAction::Direct) | None => (vec![], None),
            Some(OutboundAction::Server(server_name)) => {
                let server_config = crate::global::get_global_config().core.outbound_client.get(&server_name);
                let server_config = server_config.unwrap();

                match server_config.protocol {
                    OutboundClientProtocol::Http => {
                        wd_log::log_debug_ln!("get_proxy_client :: use ProxyClientHttp");
                        (
                            vec![Box::new(HttpTunnelProtocolClientStation::new(target.clone()))],
                            Some(HostAddress::from(server_config.addr.clone())),
                        )
                    }
                    OutboundClientProtocol::HttpOverTls => unreachable!(),
                }
            }
        };

    Ok((protocol_stations, server_address))
}
