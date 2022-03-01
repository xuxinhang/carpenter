use std::cell::RefCell;
use std::rc::Rc;
use crate::dnsresolver::DnsCacheHolder;
use crate::configuration::GlobalConfiguration;


pub struct GlobalStuff {
    pub dns_cache: DnsCacheHolder,
}


#[allow(non_upper_case_globals)]
static mut glb_stuff_ptr: *mut RefCell<GlobalStuff> = 0 as *mut _;
#[allow(non_upper_case_globals)]
static mut glb_config_ptr: *const Rc<GlobalConfiguration> = 0 as *const _;


pub fn init_global_stuff() {
    let global_stuff = RefCell::new(GlobalStuff {
        dns_cache: DnsCacheHolder::new(),
    });
    unsafe {
        glb_stuff_ptr = Box::leak(Box::new(global_stuff)) as *mut _;
    };
}

pub fn publish_global_config(global_config: Rc<GlobalConfiguration>) {
    unsafe {
        glb_config_ptr = Box::leak(Box::new(global_config)) as *mut _;
    }
}

pub fn get_global_stuff() -> &'static mut RefCell<GlobalStuff> {
    unsafe { &mut *glb_stuff_ptr }
}

pub fn get_global_config() -> &'static Rc<GlobalConfiguration> {
    unsafe { & *glb_config_ptr }
}

