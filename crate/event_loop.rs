// Anything about the event loop.
use std::io;
use std::collections::HashMap;
use mio::{Events, Interest, Poll, Token};
use mio::event::{Event, Source};


pub trait EventHandler {
    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop);
    fn register(&mut self, _registry: &mut EventRegistryIntf) -> io::Result<()> { Ok(()) }
    fn reregister(&mut self, _registry: &mut EventRegistryIntf) -> io::Result<()> { Ok(()) }
}

pub struct EventRegistryIntf(usize, Token, Interest);

impl EventRegistryIntf {
    pub fn get_event_loop(&mut self) -> &mut EventLoop {
        let offset = self.0;
        let ptr = self as *mut EventRegistryIntf as usize - offset;
        unsafe { (ptr as *mut EventLoop).as_mut().unwrap() }
    }

    pub fn register(
        &mut self,
        source: &mut dyn Source,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let el = self.get_event_loop();
        let sum_of_interests = match el.handlers.get(&token) {
            None => {
                el.handlers.insert(token, Vec::new());
                interests
            }
            Some(lst) => {
                lst.iter().fold(interests, |s, x| s | x.0)
            }
        };
        el.poll.registry().register(source, token, sum_of_interests)?;
        self.1 = token;
        self.2 = interests;
        Ok(())
    }

    pub fn reregister(
        &mut self,
        source: &mut dyn Source,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let el = self.get_event_loop();
        let sum_of_interests = match el.handlers.get(&token) {
            None => {
                el.handlers.insert(token, Vec::new());
                interests
            }
            Some(lst) => {
                lst.iter().fold(interests, |s, x| s | x.0)
            }
        };
        el.poll.registry().reregister(source, token, sum_of_interests)?;
        self.1 = token;
        self.2 = interests;
        Ok(())
    }
}


pub struct EventLoop {
    poll: Poll,
    events: Events,
    handlers: HashMap<Token, Vec<(Interest, Box<dyn EventHandler>)>>,
    registry_intf: EventRegistryIntf,
}

impl EventLoop {
    pub fn new(event_capacity: usize) -> io::Result<Self> {
        let mut this = EventLoop {
            poll: Poll::new()?,
            events: Events::with_capacity(event_capacity),
            handlers: HashMap::new(),
            registry_intf: EventRegistryIntf(0, Token(0), Interest::READABLE),
        };
        this.registry_intf.0 = (&mut this.registry_intf as *mut _ as usize) - (&mut this as *mut _ as usize);
        Ok(this)
    }

    pub fn register(&mut self, mut hdlr: Box<dyn EventHandler>) -> io::Result<()> {
        hdlr.as_mut().register(&mut self.registry_intf)?;
        self.handlers.get_mut(&self.registry_intf.1).unwrap().push((self.registry_intf.2, hdlr));
        Ok(())
    }

    pub fn reregister(&mut self, mut hdlr: Box<dyn EventHandler>) -> io::Result<()> {
        hdlr.as_mut().reregister(&mut self.registry_intf)?;
        self.handlers.get_mut(&self.registry_intf.1).unwrap().push((self.registry_intf.2, hdlr));
        Ok(())
    }

    // pub fn deregister(&mut self, hdlr: Box<dyn EventHandler>) -> io::Result<Box<dyn EventHandler>> {
    //     let mut hdlr_box = hdlr;
    //     let (source, tok, _interest) = hdlr_box.target().get();
    //     self.poll.registry().deregister(source)?;
    //     let rmd = self.handlers.remove(&tok).unwrap();
    //     Ok(rmd)
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
                if self.handlers.get(&tok).is_none() {
                    continue;
                }
                let mut pending_hdlr_idx = Vec::new();
                let hdlr_lst = self.handlers.get_mut(&tok).unwrap();
                for (idx, (inte, _)) in hdlr_lst.iter().enumerate() {
                    if interest_and_event(inte, &evt).is_some() {
                        pending_hdlr_idx.push(idx);
                    }
                }
                pending_hdlr_idx.reverse();

                let mut pending_hdlr_box = Vec::from_iter(pending_hdlr_idx.iter().map(|x| {
                    let (_, hdlr) = hdlr_lst.remove(*x);
                    hdlr
                }));
                while !pending_hdlr_box.is_empty() {
                    pending_hdlr_box.pop().unwrap().handle(&evt, self);
                }
                // remove useless items
                let hdlr_lst = self.handlers.get_mut(&tok).unwrap();
                if hdlr_lst.is_empty() {
                    self.handlers.remove(&tok);
                }
            }
        }
    }
}


fn interest_and_event(interest: &Interest, event: &Event) -> Option<Interest> {
    let mut res = None;
    let mut res_add = |i: Interest| {
        res = match res {
            None => Some(i),
            Some(p) => Some(p.add(i)),
        };
    };

    if event.is_readable() && interest.is_readable() {
        res_add(Interest::READABLE);
    }
    if event.is_writable() && interest.is_writable() {
        res_add(Interest::WRITABLE);
    }
    // if event.is_aio() && interest.is_aio() {
    //     res_add(Interest::AIO);
    // }
    // if event.is_lio() && interest.is_lio() {
    //     res_add(Interest::LIO);
    // }

    res
}
