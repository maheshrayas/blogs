# 03- Lets understand Kprobes & Kretprobes

When it comes to tracing the Linux kernel, kprobes and kretprobes are some of the oldest and most flexible tools in the eBPF ecosystem. In fact, [kprobes](https://lwn.net/Articles/132196/) were introduced long before eBPF, first appearing in Linux kernel 2.6.9 (2004), enabling dynamic tracing of almost any kernel function without requiring kernel recompilation.

eBPF came later (around kernel 3.15+) and builds upon kprobes by allowing users to attach safe, sandboxed, and highly programmable code to kernel functions, including kprobes and kretprobes. This combination provides a powerful foundation for modern observability and performance tooling.

While kprobes and kretprobes typically have higher overhead compared to other eBPF program types like XDP or tracepoints, their versatility makes them invaluable. They can attach to virtually any kernel function, enabling deep visibility into system behavior — which is why they are widely adopted in many popular eBPF-based observability tools.

*Note: Kprobe cannot probe the [blacklist function](https://www.kernel.org/doc/html/latest/trace/kprobes.html#blacklist)*


## Inner workings

With kprobes, you can attach custom eBPF programs to nearly any kernel function. When that function is called, the attached eBPF program is triggered at its **entry point**, then the original function continues as usual.
If you want to know the details on how kprobe works, I would recommend reading https://www.kernel.org/doc/html/latest/trace/kprobes.html#how-does-a-kprobe-work


In contrast, **kretprobes** are triggered when the function **returns**. This allows you to capture return values or output arguments — making them ideal for debugging, performance monitoring, or return-value-based logic.

In this post, we’ll demonstrate how to trace HTTP/1.1 headers using kprobes and extract them for observability. Since SSL/TLS encrypts the payload, this technique only applies to unencrypted HTTP traffic.

In a future post, we'll explore how to trace HTTP/2 (gRPC) headers using uprobes, which allow visibility into user-space libraries like golang.org/x/net/http2.

More details on Probing eBPF: 
* docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE
* https://www.kernel.org/doc/html/latest/trace/kprobes.html


## Before we dive into examples

Kprobes provide unmatched flexibility to dynamically instrument almost any kernel function. However, attaching probes indiscriminately can introduce performance overhead or stability risks. It’s best practice to:

* Target well-known, stable kernel functions related to syscalls, networking, or drivers.

* Confirm symbol presence and type in `/proc/kallsyms` (look for uppercase T symbols).

* Test probes carefully on a non-production system.

Keep in mind kernel version differences and module load/unload events may affect probe reliability.

Typical kprobe targets include kernel functions related to syscalls, networking stacks, drivers, and filesystem operations, enabling tracing of specific kernel events.

**Performance impact**: Kprobes add instrumentation overhead because they inject code on function entry or return. While usually small, probing high-frequency functions can cause noticeable CPU overhead. Hence needs to be performance tested before its production ready.

`/proc/kallsyms` is a special file in Linux that lists all currently loaded kernel symbols, including function names, memory addresses, and variable symbols. This file is particularly useful when working with kprobes, as it helps identify kernel functions that can be dynamically instrumented.

You can find all the symbols using

```bash
sudo cat /proc/kallsyms
```

However, it’s important to note:

* Function availability can differ based on kernel version, architecture (e.g., x86 vs ARM), and build configurations.

* Some symbols may be inlined, optimized away, or renamed in newer kernels.

So, when writing portable eBPF programs using kprobes, always validate your target symbol on the specific kernel using /proc/kallsyms.

for example 
```bash

> sudo cat /proc/kallsyms | grep "sys_read"


ffffffffb52edf30 T __pfx___x64_sys_read
ffffffffb52edf40 T __x64_sys_read
ffffffffb52edf70 T __pfx___ia32_sys_read
ffffffffb52edf80 T __ia32_sys_read
```

Symbols marked with `T` indicate global (exported) kernel text symbols, i.e., functions you can reliably attach kprobes to.

## Let's Dive into the Example

Working example: [TODO: Add GitHub or Repo Link]

This example traces HTTP/1.1 headers of a server using eBPF. Here's the setup:

1. The HTTP server exposes a basic REST API and is not SSL encrypted. This is important because we cannot trace encrypted data in the kernel—encryption and decryption happen in user-space libraries like OpenSSL.

2. A Rust user-space application is run, and the PID of the HTTP server is supplied as input.

3. The user-space program loads and attaches kprobes to relevant kernel functions (explained in detail below).

4. From user-space, we update an eBPF map to track the PID.

⚠️ Note: In containerized environments, the PID inside a container differs from what the host kernel sees. So, we must trace using the host PID and map it the container/pod process id. This becomes important when we later build a tool to trace pod/container processes from the host.

```rust
let key = pid.to_ne_bytes();
let value = 1u8.to_ne_bytes();
if let Err(_) = http_sk.maps.tracked_pids.update(&key, &value, MapFlags::ANY){
    warn!("failed to update maps for pid {}\n",pid);
}
```
### eBPF Program Logic

We attach three probes to two different kernel functions.

1. `kretprobe/__sys_accept4` -> handle_accept4_ret

The first kretprobe is attached to the kernel function __sys_accept4, which is invoked during the accept4() syscall.
This is where a server accepts a new incoming connection.

* From this kretprobe, we extract the file descriptor (fd) returned by accept4.

* We check if the calling process's PID exists in the `tracked_pids` map.

* If it matches, we store the new fd in another eBPF map called `active_app_sockets`.

```c
SEC("kretprobe/__sys_accept4")
int handle_accept4_ret(struct pt_regs *ctx)
{
    int new_fd = PT_REGS_RC(ctx);
    //// Logic to filter and store fd
}

```


2. `kprobe/ksys_read` -> kprobe_ksys_read_entry

This kprobe is attached to the `ksys_read()` kernel function, which is called when a process reads from an fd.

* We check if the `fd` is already in the `active_app_sockets` map.

* If yes, we store the `buf` pointer in the `read_args_map`.

```c
SEC("kprobe/ksys_read")
int kprobe_ksys_read_entry(struct pt_regs *ctx)
{
    // Check if fd is tracked
    // Save the 'buf' argument into a map for use in the return probe
}


```
What is buf?

* The buf argument is a pointer to a user-space memory buffer.

* The kernel will copy data into this buffer as a result of the read syscall.

* Since eBPF programs run in kernel space, accessing this pointer directly is not safe or valid unless we carefully copy from user memory using helpers like `bpf_probe_read_user`.


3.  `kretprobe/ksys_read` -> kretprobe_ksys_read_exit 

Once the syscall ksys_read() is invoked, the actual data is not yet read into user space — it happens later, by the time the function returns. Therefore, to access the actual read data, we attach a kretprobe to ksys_read. This allows us to retrieve the number of bytes that were read and use that length to copy the data from user space buffer.

```c
SEC("kretprobe/ksys_read")
int kretprobe_ksys_read_exit(struct pt_regs *ctx)
{
    // Get the Pid 
    // Read the actual data using bpf_probe_read_user
    // Check if its HTTP data
    // and send it the data to user space if the pid is that of http server.
}

```

4. Parsing Perf Event Data in Userspace

The user-space process continuously polls the perf event array for incoming data. Once data is received, it parses the raw binary payload emitted from the eBPF program.

One critical aspect to consider during this parsing step is struct alignment and memory layout compatibility between kernel space (C) and user space (Rust). When decoding the raw binary data from the perf buffer into a Rust struct, the layout of the Rust struct must exactly match the layout of the C struct used in the eBPF program.

To ensure compatibility:

* Use the same field order and types in your Rust struct.

* Add the #[repr(C)] attribute to enforce C-like memory layout in Rust.

This ensures safe and correct parsing of the data, avoiding undefined behavior due to padding or misalignment between the two languages.

```Rust
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
   //...
}

```

## Wrapping Up

In this post, we explored:

* How to use kprobes and kretprobes to trace syscalls like `ksys_read` & `accept`, paving the way to trace HTTP headers.

* How to capture user-space data (like HTTP headers) inside the kernel using eBPF.

* Safe parsing of raw perf event data in Rust, using #[repr(C)] and field alignment.

This lays the groundwork for powerful observability tools that require no code changes in the application layer — everything is captured transparently from the kernel.

## What's Next?

In the next part of this series, we'll explore how to parse gRPC headers from a Go HTTP/2 server, diving deeper into protocol parsing. 
Later, we’ll bring everything together to build a Kubernetes-native observability tool that can trace HTTP headers — all without any modification or instrumentation to the applications themselves.

Stay tuned — it gets even more exciting from here!

