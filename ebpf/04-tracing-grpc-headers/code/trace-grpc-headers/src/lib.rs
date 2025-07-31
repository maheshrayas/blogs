pub mod go_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/go.skel.rs"
    ));
}
pub mod grpc_probe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/grpc.skel.rs"
    ));
}
pub mod log;
pub mod common;
