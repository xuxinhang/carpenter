use crate::bridge::BridgeStation;
use crate::common::HostAddress;

pub struct RemoteLinkGuide {
    pub stream_target: HostAddress,
    pub stations: Vec<Box<dyn BridgeStation>>,
    pub client_station_index: Option<usize>,
}

pub fn get_default_remote_link (target: HostAddress) -> RemoteLinkGuide {
    RemoteLinkGuide {
        stream_target: target,
        stations: vec![],
        client_station_index: None,
    }
}
