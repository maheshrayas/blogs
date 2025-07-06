pub mod syscall_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}
pub mod log;
