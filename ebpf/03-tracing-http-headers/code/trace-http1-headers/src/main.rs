use std::{
    env,
    error::Error,
    mem::MaybeUninit,
};

use tokio::time::Duration;
use tracing::{error, info, warn};
use libbpf_rs::{
    MapCore,
    MapFlags,
    PerfBufferBuilder,
};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

use trace_http1_headers::{
    http_probe::*,
    log::init_logger,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HttpEventData {
    pid: u32,
    fd: i32,
    data_len: u32,
    data: [u8; 256],
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const HttpEventData) };

    // Convert the raw data to a string
    let data_slice = &event.data[..event.data_len as usize];
    if let Ok(http_data) = std::str::from_utf8(data_slice) {
        info!("HTTP Event - PID: {}, FD: {}", event.pid, event.fd);
        parse_http_headers(http_data);
    } else {
        warn!("Non-UTF8 data received from PID {}", event.pid);
    }
}

fn parse_http_headers(http_data: &str) {
    let lines: Vec<&str> = http_data.split('\n').collect();

    if let Some(request_line) = lines.first() {
        info!("Request: {}", request_line.trim());
    }

    for line in lines.iter().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }

        if let Some((key, value)) = trimmed.split_once(':') {
            info!("Header: {} = {}", key.trim(), value.trim());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    // args 0 -> binary
    // args 1 -> pid
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <pid>", args[0]);
        std::process::exit(1);
    }
    
    let pid: u32 = args[1].parse().map_err(|_| {
        eprintln!("Error: '{}' is not a valid PID", args[1]);
        std::process::exit(1);
    })?;

    let mut open_object = MaybeUninit::uninit();
    let skel_builder = HttpSkelBuilder::default();
    let http_probe_skel = skel_builder.open(&mut open_object)?;
    let mut http_sk = http_probe_skel.load()?;
    let _ = http_sk.attach().map_err(|e| {
        error!("failed to attach the ebpf program {}", e);
        e
    })?;
    info!("eBPF program loaded and attached successfully");
    let perf_buffer = PerfBufferBuilder::new(&http_sk.maps.http_events)
        .sample_cb(handle_event)
        .build()?;


    let key = pid.to_ne_bytes();
    let value = 1u8.to_ne_bytes();
    if let Err(_) = http_sk.maps.tracked_pids.update(&key, &value, MapFlags::ANY){
        warn!("failed to update maps for pid {}\n",pid);
    }
    

    info!("Starting to poll for events...");
    loop {
        perf_buffer.poll(Duration::from_millis(100))?;
    }
}
