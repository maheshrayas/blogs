# trace-grpc-headers

A toolkit for tracing Go and gRPC function arguments using eBPF.

---

## Prerequisites

- Go 1.17 or newer
- [grpcurl](https://github.com/fullstorydev/grpcurl)
- [cross](https://github.com/cross-rs/cross) (for building Rust binaries)
- Linux with eBPF support

---

## Tracing Go Function Arguments

### 1. Build and Run the Sample Go Binary

```bash
cd sample_go
./build.sh
```

### 2. Build and Load the eBPF Tracer

```bash
cross build --release --target x86_64-unknown-linux-gnu --bin go
```

### 3. Attach the eBPF Program

```bash
sudo ./target/x86_64-unknown-linux-gnu/release/go \
  --pid <PID_OF_SAMPLE_GO> \
  --binary-func <FUNCTION_NAME> \
  --binary-name sample \
  --bp ./blogs/ebpf/04-tracing-grpc-headers/code/sample_go
```

**Supported `--binary-func` values:**
- `main.hello_struct_value`
- `main.hello_int`
- `main.hello_int_string`
- `main.hello_struct_pointer`

### 4. View Traces

Open a separate terminal and run:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

---

## Tracing gRPC Headers

### 1. Build and Run the Sample gRPC Server

```bash
cd sample_grpc
./build.sh
```

### 2. Build and Load the eBPF Tracer

Open another terminal:

```bash
cd trace-grpc-headers
cross build --release --target x86_64-unknown-linux-gnu --bin grpc
sudo ./target/x86_64-unknown-linux-gnu/release/grpc \
  --pid <PID_OF_GRPC_SERVER> \
  --binary-name grpc \
  --bp ./blogs/ebpf/04-tracing-grpc-headers/code/sample_grpc
```

### 3. View Traces

Open a separate terminal and run:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

### 4. Trigger the gRPC Service

Open another terminal and execute:

```bash
cd sample_grpc

grpcurl -plaintext \
  -import-path ./proto \
  -proto helloworld.proto \
  -d '{"name": "JamesBond"}' \
  localhost:50051 \
  helloworld.Greeter/SayHello
```

---

## Notes

- Ensure you have the necessary permissions to run eBPF programs (typically requires `sudo`).
- Adjust paths as needed for your environment.
- For troubleshooting, check kernel logs and ensure your Go and Rust toolchains are correctly set up.



