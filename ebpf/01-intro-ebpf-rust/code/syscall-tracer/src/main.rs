use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::{error::Error, mem::MaybeUninit};
use tokio::time::Duration;

use syscall_tracer::log::init_logger;
use syscall_tracer::syscall_probe::*;
use tracing::{error, info};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DataT {
    pid: u64,
    sysnbr: u64,
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const DataT) };
    info!(
        "Syscall event: PID={}, Syscall number={}",
        event.pid, event.sysnbr
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    let mut open_object = MaybeUninit::uninit();
    let skel_builder = SyscallSkelBuilder::default();
    let syscall_probe_skel = skel_builder.open(&mut open_object)?;
    let mut syscall_sk = syscall_probe_skel.load()?;
    let _ = syscall_sk.attach().map_err(|e| {
        error!("failed to attach the ebpf program {}", e);
        e
    })?;

    info!("eBPF program loaded and attached successfully");

    let perf_buffer = PerfBufferBuilder::new(&syscall_sk.maps.syscall_events)
        .sample_cb(handle_event)
        .build()?;

    info!("Starting to poll for events...");
    loop {
        perf_buffer.poll(Duration::from_millis(100))?;
    }
}
