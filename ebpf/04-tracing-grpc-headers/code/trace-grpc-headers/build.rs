use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;
use vmlinux;

const GO_SRC: &str = "src/bpf/go.bpf.c";
const GRPC_SRC: &str = "src/bpf/grpc.bpf.c";

fn main() {
    let go = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("go.skel.rs");

    let grpc = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("grpc.skel.rs");


    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(GO_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&go)
        .unwrap();
    
    SkeletonBuilder::new()
        .source(GRPC_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&grpc)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf");
}
