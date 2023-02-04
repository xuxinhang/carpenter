pub mod base;
pub mod buffer;
pub mod streambuffer;
pub mod certstorage;
pub mod direct;
pub mod sniomit;
pub mod directconnect;
pub mod httpforward;
pub mod sni;


pub use base::{TunnelTransformer, TransferResult};
pub use base::{Transformer, TransformerResult, TransformerPortState};

pub use base::{TransformerUnit, TransformerUnitResult, TransformerUnitError};

pub use directconnect::DirectConnectionTransformer;
pub use httpforward::HttpForwardTransformer;
pub use sni::SniRewriterTransformer;



use std::str::FromStr;
use crate::configuration::{TransformerAction};
use crate::common::{HostName, HostAddr};

pub fn create_transformer(host: &HostAddr, use_http_tunnel: bool) -> std::io::Result<Box<dyn Transformer>> {
    let global_config = crate::global::get_global_config();
    let transformer_config = global_config.get_transformer_action_by_host(host);

    if use_http_tunnel == false {
        return Ok(Box::new(HttpForwardTransformer::new(host.clone())));
    }

    let transformer_box: Box<dyn Transformer> = match transformer_config {
        Some(TransformerAction::SniTransformer(s)) => {
            let sni_name = match s.as_str() {
                "_" => None,
                "*" => Some(host.0.clone()),
                h => {
                    if let Ok(x) = HostName::from_str(h) {
                        Some(x)
                    } else {
                        wd_log::log_warn_ln!("Invalid hostname {}", h);
                        Some(host.0.clone())
                    }
                }
            };
            wd_log::log_info_ln!("Use transformer: SNI Rewritter \"{}\"",
                if let Some(ref v) = sni_name { v.to_string() } else { "<omitted>".to_string() });
            let transformer = SniRewriterTransformer::new("", sni_name, host.0.clone());
            if let Err(e) = transformer {
                wd_log::log_info_ln!("ProxyQueryDoneCallback # SniRewriterTransformer::new {:?}", e);
                return Err(e);
            }
            Box::new(transformer.unwrap())
        }
        Some(TransformerAction::DirectTransformer) | None => {
            wd_log::log_info_ln!("Use transformer: Direct");
            Box::new(DirectConnectionTransformer::new())
        }
    };

    return Ok(transformer_box);
}


pub fn create_transformer_unit(host: &HostAddr, _use_http_tunnel: bool)
    -> std::io::Result<Box<dyn TransformerUnit>> {
    let global_config = crate::global::get_global_config();
    let transformer_config = global_config.get_transformer_action_by_host(host);

    // if use_http_tunnel == false {
    //     return Ok(Box::new(HttpForwardTransformer::new(host.clone())));
    // }

    let transformer_box: Box<dyn TransformerUnit> = match transformer_config {
        // Some(TransformerAction::SniTransformer(s)) => {
        //     let sni_name = match s.as_str() {
        //         "_" => None,
        //         "*" => Some(host.0.clone()),
        //         h => {
        //             if let Ok(x) = HostName::from_str(h) {
        //                 Some(x)
        //             } else {
        //                 wd_log::log_warn_ln!("Invalid hostname {}", h);
        //                 Some(host.0.clone())
        //             }
        //         }
        //     };
        //     wd_log::log_info_ln!("Use transformer: SNI Rewritter \"{}\"",
        //         if let Some(ref v) = sni_name { v.to_string() } else { "<omitted>".to_string() });
        //     let transformer = SniRewriterTransformer::new("", sni_name, host.0.clone());
        //     if let Err(e) = transformer {
        //         wd_log::log_info_ln!("ProxyQueryDoneCallback # SniRewriterTransformer::new {:?}", e);
        //         return Err(e);
        //     }
        //     Box::new(transformer.unwrap())
        // }
        Some(TransformerAction::SniTransformer(_)) | Some(TransformerAction::DirectTransformer) | None => {
            wd_log::log_info_ln!("Use transformer: Direct");
            Box::new(DirectConnectionTransformer::new())
        }
    };

    return Ok(transformer_box);
}
