
#[derive(PartialEq, Debug)]
pub enum TlsClosingStage {
    Running,
    PeerSentCloseNotify,
    HereSentCloseNotify,
    BothSentCloseNotify,
    Crushed,
}

impl TlsClosingStage {
    pub fn peer_closing(&self) -> bool {
        matches!(self, TlsClosingStage::BothSentCloseNotify | TlsClosingStage::PeerSentCloseNotify)
    }
    pub fn here_closing(&self) -> bool {
        matches!(self, TlsClosingStage::HereSentCloseNotify | TlsClosingStage::BothSentCloseNotify)
    }
    pub fn both_closed(&self) -> bool {
        matches!(self, TlsClosingStage::BothSentCloseNotify | TlsClosingStage::Crushed)
    }
}
