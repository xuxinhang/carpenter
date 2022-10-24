use mio::{Interest, Token};
use mio::event::{Event};


struct EventTokenPool {
    next_token: Token,
}

impl EventTokenPool {
    pub fn get(&mut self) -> Token {
        let t = self.next_token;
        self.next_token = Token(self.next_token.0 + 1);
        return t;
    }
}
