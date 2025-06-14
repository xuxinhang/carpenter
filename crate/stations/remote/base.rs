use std::{io, str::FromStr};
use crate::bridge::{BridgeStation, BridgeStationTransferRecord};
use crate::common::{convert_HostAddress_to_HostAddr, HostAddress, Hostname};
use crate::configuration::TransformerAction;
use crate::stations::modifiers::tls_packer::{TlsRepackerStation, TlsUnpackerStation};
use crate::transformer::{DirectConnectionTransformer, HttpForwardTransformer, SniRewriterTransformer, TransformerUnit};

pub struct RemoteLinkGuide {
    pub stream_target: HostAddress,
    pub stations: Vec<Box<dyn BridgeStation>>,
    pub client_station_index: Option<usize>,
}

pub fn get_default_remote_link (target: HostAddress) -> RemoteLinkGuide {
    let modifier_stations = get_modifier_stations(&target).unwrap();

    let mut sum_stations = Vec::new();
    sum_stations.extend(modifier_stations);

    RemoteLinkGuide {
        stream_target: target,
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
            wd_log::log_info_ln!("Use transformer: SNI Rewritter \"{}\"",
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
