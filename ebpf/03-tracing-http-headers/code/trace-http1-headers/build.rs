use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;
use vmlinux;

const HTTP_SRC: &str = "src/bpf/http.bpf.c";

fn main() {
    let http = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("http.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(HTTP_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&http)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf");
}
