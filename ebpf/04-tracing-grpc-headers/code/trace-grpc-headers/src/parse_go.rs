use std::{ error::Error, mem::MaybeUninit};
use std::path::PathBuf;
use std::thread::sleep;

use clap::Parser;
use libbpf_rs::skel::{OpenSkel,SkelBuilder};
use tokio::time::Duration;

use trace_grpc_headers::common::{get_load_base, get_symbol_address};
use trace_grpc_headers::{go_probe::*, log::init_logger};


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PID of the target process
    #[arg(long)]
    pid: i32,

    /// Fully qualified function name to trace
    #[arg(long)]
    binary_func: String,

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
    let binary_func = args.binary_func;
    let binary_name = args.binary_name;
    let bp = args.bp;
    let binary_path = PathBuf::from(format!("{}/{}", bp, binary_name));

    let symbol_address = get_symbol_address(&binary_path, &binary_func).unwrap();

    let load_base = get_load_base(pid as u32, &binary_name).unwrap();
    let offset = symbol_address - load_base;

    let mut open_object: MaybeUninit<libbpf_rs::OpenObject> = MaybeUninit::uninit();
    let skel_builder = GoSkelBuilder::default();
    let go_probe_skel = skel_builder.open(&mut open_object).unwrap();
    let go_sk = go_probe_skel.load().unwrap();

    // Match the function name to the correct field on go_sk.progs
    let r = match binary_func.as_str() {
        "main.hello_int" => {
            go_sk
                .progs
                .handle_hello_int
                .attach_uprobe(false, pid, &binary_path, offset as usize)
        }
        "main.hello_int_string" => go_sk.progs.handle_hello_int_string.attach_uprobe(
            false,
            pid,
            &binary_path,
            offset as usize,
        ),
        "main.hello_struct_pointer" => go_sk.progs.handle_hello_struct_pointer.attach_uprobe(
            false,
            pid,
            &binary_path,
            offset as usize,
        ),
        "main.hello_struct_value" => go_sk.progs.handle_hello_struct_value.attach_uprobe(
            false,
            pid,
            &binary_path,
            offset as usize,
        ),
    
        _ => return Err(format!("Unknown function: {}", binary_func).into()),
    }?;

    loop {
        sleep(Duration::from_millis(100));
    }
}

