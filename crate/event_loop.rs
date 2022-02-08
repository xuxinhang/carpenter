// Anything about the event loop.
use std::io;
use std::collections::HashMap;
use mio::{Events, Interest, Poll, Token};
use mio::event::{Event, Source};


pub trait EventHandler {
    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop);
    fn target(&mut self) -> (&mut dyn Source, Token, Interest);
}

pub struct EventLoop {
    poll: Poll,
    events: Events,
    handlers: HashMap<Token, Box<dyn EventHandler>>,
}

impl EventLoop {
    pub fn new(event_capacity: usize) -> io::Result<Self> {
        Ok(EventLoop {
            poll: Poll::new()?,
            events: Events::with_capacity(event_capacity),
            handlers: HashMap::new(),
        })
    }

    pub fn register(&mut self, hdlr: Box<dyn EventHandler>) -> io::Result<Token> {
        let mut hdlr_box = hdlr;
        let hdlr_mut = hdlr_box.as_mut();
        let (source, tok, interest) = hdlr_mut.target();
        self.poll.registry().register(source, tok, interest)?;
        match self.handlers.insert(tok, hdlr_box) {
            Some(_) => {
                println!("ERROR: Handler token rewritten.");
            }
            None => {}
        }
        Ok(tok)
    }

    pub fn reregister(&mut self, hdlr: Box<dyn EventHandler>) -> io::Result<Token> {
        let mut hdlr_box: Box<dyn EventHandler> = hdlr;
        let hdlr_mut = hdlr_box.as_mut();
        let (source, tok, interest) = hdlr_mut.target();
        self.poll.registry().reregister(source, tok, interest)?;
        match self.handlers.insert(tok, hdlr_box) {
            Some(_) => {
                println!("ERROR: Handler token rewritten.");
            }
            None => {}
        }
        Ok(tok)
    }

    pub fn reregisteri(&mut self, hdlr: Box<dyn EventHandler>, interest: Interest) -> io::Result<Token> {
        let mut hdlr_box: Box<dyn EventHandler> = hdlr;
        let hdlr_mut = hdlr_box.as_mut();
        let (source, tok, _) = hdlr_mut.target();
        self.poll.registry().reregister(source, tok, interest)?;
        match self.handlers.insert(tok, hdlr_box) {
            Some(_) => {
                println!("ERROR: Handler token rewritten.");
            }
            None => {}
        }
        Ok(tok)
    }

    pub fn deregister(&mut self, hdlr: Box<dyn EventHandler>) -> io::Result<Box<dyn EventHandler>> {
        let mut hdlr_box = hdlr;
        let (source, tok, _interest) = hdlr_box.target();
        self.poll.registry().deregister(source)?;
        let rmd = self.handlers.remove(&tok).unwrap();
        Ok(rmd)
    }

    pub fn start_loop(&mut self) -> io::Result<()> {
        loop {
            self.poll.poll(&mut self.events, None)?;

            let mut pending_events: Vec<(Event, Token)> = Vec::new();

            for event in self.events.iter() {
                let tok = event.token();
                pending_events.push((event.clone(), tok));
            }

            for (evt, tok) in pending_events {
                let hdlr = self.handlers.remove(&tok).unwrap();
                hdlr.handle(&evt, self);
            }
        }
    }
}

