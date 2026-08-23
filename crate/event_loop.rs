// Anything about the event loop.
use std::io;
use std::collections::HashMap;
use mio::{Events, Interest, Poll, Token};
use mio::event::{Event, Source};
use std::time::SystemTime;


pub struct EventTokenPool {
    next_token: Token,
}

impl EventTokenPool {
    pub fn get(&mut self) -> Token {
        let t = self.next_token;
        self.next_token = Token(self.next_token.0 + 1);
        t
    }
}


pub trait EventHandler {
    fn get_tag(&self) -> &'static str { "GenericEventHandle" }
    fn collect(&mut self, _registry: &mut EventRegistryIntf) -> io::Result<()> { Ok(()) }
    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop);
}


pub struct EventRegistryIntf(usize, Token, Interest, usize);

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
        let handler_id = self.3;
        self.get_event_loop().poll.registry().register(source, token, interests)?;
        self.1 = token.clone();
        self.2 = interests;
        self.get_event_loop().listens.push(EventListen {
            token: token.clone(),
            interest: interests.clone(),
            handler_id,
        });
        Ok(())
    }

    pub fn reregister(
        &mut self,
        source: &mut dyn Source,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let handler_id = self.3;
        self.get_event_loop().poll.registry().reregister(source, token, interests)?;
        self.1 = token;
        self.2 = interests;
        self.get_event_loop().listens.push(EventListen {
            token: token.clone(),
            interest: interests.clone(),
            handler_id,
        });
        Ok(())
    }
}


struct EventListen {
    pub token: Token,
    pub interest: Interest,
    pub handler_id: usize,
}


pub struct EventLoop {
    poll: Poll,
    registry_intf: EventRegistryIntf,
    handler_id_count: usize,
    handlers: HashMap<usize, Box<dyn EventHandler>>,
    listens: Vec<EventListen>,
    pub token: EventTokenPool,
}

impl EventLoop {
    pub fn new() -> io::Result<Self> {
        let mut this = EventLoop {
            poll: Poll::new()?,
            handlers: HashMap::new(),
            registry_intf: EventRegistryIntf(0, Token(0), Interest::READABLE, 0),
            token: EventTokenPool { next_token: Token(256) },
            listens: Vec::new(),
            handler_id_count: 100,
        };
        this.registry_intf.0 = (&mut this.registry_intf as *mut _ as usize) - (&mut this as *mut _ as usize);
        Ok(this)
    }

    pub fn collect(&mut self, mut hdlr: Box<dyn EventHandler>) -> io::Result<()> {
        self.registry_intf.3 = self.handler_id_count;
        hdlr.as_mut().collect(&mut self.registry_intf)?;
        self.handlers.insert(self.registry_intf.3, hdlr);
        self.handler_id_count += 1;
        Ok(())
    }

    pub fn start_loop(&mut self) -> io::Result<()> {
        const EVENTS_CAPACITY: usize = 64;
        
        loop {
            let mut poll_events = Events::with_capacity(EVENTS_CAPACITY);
            self.poll.poll(&mut poll_events, None)?;

            for evt in poll_events.iter() {
                let tok = evt.token();

                let active_listens_idx: Vec<usize> =
                    (0..self.listens.len())
                        .filter(|&li| {
                            let lx = &self.listens[li];
                            tok == lx.token && interest_and_event(&lx.interest, &evt).is_some()
                        })
                        .collect();

                let mut active_handlers = Vec::new();

                for li in &active_listens_idx {
                    let lx = &self.listens[*li];
                    if let Some(handler) = self.handlers.remove(&lx.handler_id) {
                        active_handlers.push((handler, lx.handler_id));
                    }
                }

                for (_, handler_id) in &active_handlers {
                    self.listens.retain(|lx| lx.handler_id != *handler_id);
                }

                for (handler, _handler_id) in active_handlers {
                    let before_time = SystemTime::now();
                    let tag_str = handler.get_tag();
                    handler.handle(&evt, self);
                    let after_time = SystemTime::now();
                    let duration_sec = after_time.duration_since(before_time).unwrap().as_secs();
                    if duration_sec > 2 {
                        wd_log::log_error_ln!("[EventLoop] handler {} spends too long time {} seconds", duration_sec, tag_str);
                    }
                }

                self.clean_garbage();
            }
        }
    }

    fn clean_garbage(&mut self) {
        let referenced_handler_ids: std::collections::HashSet<usize> =
            self.listens.iter().map(|lx| lx.handler_id).collect();
        self.handlers.retain(|handler_id, _| {
            referenced_handler_ids.contains(handler_id)
        });

        self.listens.retain(|lx| {
            referenced_handler_ids.contains(&lx.handler_id)
        });

        let _after_mark = self.handlers.len() + self.listens.len();
    }
}


fn interest_and_event(interest: &Interest, event: &Event) -> Option<Interest> {
    let mut res: Option<Interest> = None;
    macro_rules! res_add {
        ($i:expr) => {
            res = res.map_or(Some($i), |r| Some(r.add($i)))
        };
    }
    if event.is_readable() && interest.is_readable() {
        res_add!(Interest::READABLE);
    }
    if event.is_writable() && interest.is_writable() {
        res_add!(Interest::WRITABLE);
    }
    res
}
