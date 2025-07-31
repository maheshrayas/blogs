use std::{ error::Error, mem::MaybeUninit};
use std::path::PathBuf;
use std::thread::sleep;

use clap::Parser;
use libbpf_rs::skel::{OpenSkel,SkelBuilder};
use tokio::time::Duration;

use trace_grpc_headers::common::{get_load_base, get_symbol_address};
use trace_grpc_headers::{grpc_probe::*, log::init_logger};


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PID of the target process
    #[arg(long)]
    pid: i32,

    /// Binary name (file name)
    #[arg(long)]
    binary_name: String,

    /// Path to the directory containing the binary
    #[arg(long)]
    bp: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    let args = Args::parse();

    let pid = args.pid;
    let binary_name = args.binary_name;
    let bp = args.bp;

    let binary_func = "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders";
    let binary_path = PathBuf::from(format!("{}/{}", bp, binary_name));

    let symbol_address = get_symbol_address(&binary_path, &binary_func).unwrap();
    let load_base = get_load_base(pid as u32, &binary_name).unwrap();
    let offset = symbol_address - load_base;

    let mut open_object: MaybeUninit<libbpf_rs::OpenObject> = MaybeUninit::uninit();
    let skel_builder = GrpcSkelBuilder::default();
    let grpc_probe_skel = skel_builder.open(&mut open_object).unwrap();
    let grpc_sk = grpc_probe_skel.load().unwrap();

    let r = grpc_sk.progs.trace_grpc_headers.attach_uprobe(false,
            pid,
            &binary_path,
            offset as usize)?;
    loop {
        sleep(Duration::from_millis(100));
    }
}

