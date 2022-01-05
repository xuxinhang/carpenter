// Anything about the event loop.
use std::io;
use std::collections::HashMap;
use mio::{Events, Interest, Poll, Token};
use mio::event::{Event, Source};


pub trait EventHandler {
    fn handle(&mut self, event: &Event, event_loop: &mut EventLoop) -> bool;
    fn target(&mut self) -> (&mut dyn Source, Interest);
}


pub struct EventLoop {
    poll: Poll,
    events: Events,
    handlers: HashMap<Token, Box<dyn EventHandler>>,
    token_count: usize,
}

impl EventLoop {
    pub fn new(event_capacity: usize) -> io::Result<Self> {
        Ok(EventLoop {
            poll: Poll::new()?,
            events: Events::with_capacity(event_capacity),
            handlers: HashMap::new(),
            token_count: 255
        })
    }

    fn get_token(&mut self) -> (usize, Token) {
        self.token_count += 1;
        (self.token_count, Token(self.token_count))
    }

    pub fn register<A: EventHandler + 'static>(&mut self, hdlr: A) -> io::Result<Token> {
        let (_sid, tok) = self.get_token();
        let mut hdlr_box = Box::new(hdlr);
        let hdlr_mut = hdlr_box.as_mut();
        let (source, interest) = hdlr_mut.target();
        self.poll.registry().register(source, tok, interest)?;
        self.handlers.insert(tok, hdlr_box);
        Ok(tok)
    }

    pub fn reregister<A: EventHandler + 'static>(&mut self, tok: Token, hdlr: A) -> io::Result<Token> {
        let mut hdlr_box = Box::new(hdlr);
        let hdlr_mut = hdlr_box.as_mut();
        let (source, interest) = hdlr_mut.target();
        self.poll.registry().reregister(source, tok, interest)?;
        self.handlers.insert(tok, hdlr_box);
        Ok(tok)
    }

    // pub fn deregister<A: EventHandler + 'static>(&mut self, hdlr: A) -> io::Result<()> {
    //     let (source, _) = hdlr.target();
    //     self.poll.registry().deregister(source.as_ref())?;
    //     // let rmd = self.handlers.remove(&usize::from(tok));
    //     Ok(())
    // }

    pub fn start_loop(&mut self) -> io::Result<()> {
        loop {
            self.poll.poll(&mut self.events, None)?;

            let mut pending_events: Vec<(Event, Token)> = Vec::new();

            for event in self.events.iter() {
                let tok = event.token();
                pending_events.push((event.clone(), tok));
            }

            for (evt, tok) in pending_events {
                // println!("Event here.");
                let mut hdlr = self.handlers.remove(&tok).unwrap();
                if hdlr.as_mut().handle(&evt, self) == true {
                    let (source, interest) = hdlr.as_mut().target();
                    self.poll.registry().reregister(source, tok, interest)?;
                    self.handlers.insert(tok, hdlr);
                }
            }
        }
    }
}

