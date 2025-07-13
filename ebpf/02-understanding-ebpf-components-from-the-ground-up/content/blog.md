# Understanding eBPF Core Building Blocks



In our previous post, we built a syscall tracer with Rust + eBPF. Today, we’ll unpack the core components that made it work — and the deeper mechanics powering real-world eBPF tools. Understanding these components will help you build more sophisticated observability, security and networking tools.

## 1. BPF Program Types & Hook Points

**Program types** define *what* the eBPF program can do, while **hook points** define *where* it runs in the kernel.

### Key Program Types:

**XDP (eXpress Data Path)**
- Runs at the **earliest** point in network packet processing
- Perfect for DDoS protection, load balancing
- Can DROP, PASS, REDIRECT, or TX packets

**TC (Traffic Control)**
- Attaches to network **ingress/egress** points
- More context than XDP, can modify packets
- Used for advanced packet filtering and shaping

**Kprobes/Kretprobes**
- Dynamic tracing of **any kernel function**
- Kprobe = function entry, Kretprobe = function return

**Uprobes/Uretprobes** 
- Trace **userspace applications** (like Go, Python apps)
- Can inspect function arguments, return values
- Great for application performance monitoring

**Tracepoints**
- **Static** kernel instrumentation points
- More stable than kprobes across kernel versions
- Predefined events like `sys_enter_openat`
- our syscall tracer used `sys_enter` !

**CGROUP**
- Control resource access per container/process group
- Implement custom policies (network, file access)

**Socket Programs**
- Filter/redirect packets at socket level
- Implement custom load balancers, firewalls


## 2. BPF Verifier: The Safety Guardian

The **BPF verifier** is what makes eBPF safe. It performs **static analysis** on the program before loading it into the kernel.

### What the Verifier Checks:

**Memory Safety**
- No out-of-bounds array access
- No null pointer dereferences
- Proper initialization of variables

**Control Flow**
- No infinite loops (bounded loops only since Linux 5.3)
- All code paths must exit
- No unreachable code

**Helper Function Usage**
- Only approved helper functions can be called
- Correct argument types and counts

**Stack Usage**
- Limited to 512 bytes of stack space
- No stack overflow protection needed

```c
// ❌ This will be REJECTED by verifier
for (int i = 0; ; i++) {  // Infinite loop
    // code
}

// ✅ This will be ACCEPTED
for (int i = 0; i < 100; i++) {  // Bounded loop
    // code  
}
```

**Why This Matters:** The verifier ensures the eBPF program cannot crash the kernel, making it safe to run in production.

## 3. BPF Maps: Data Storage & Communication

**BPF Maps** are the primary way to:
- Store state between eBPF program invocations
- Communicate between kernel and userspace
- Share data between different eBPF programs

### Essential Map Types:

**Hash Maps** - Key-value storage
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);           // PID
    __type(value, u64);         // Syscall count
} syscall_counts SEC(".maps");
```

**Arrays** - Index-based access
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);   // One per syscall number
    __type(key, u32);
    __type(value, u64);
} syscall_stats SEC(".maps");
```

**Perf Event Arrays** - High-speed data streaming

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

You can find the usage of this in the pervious blog post [code](https://github.com/maheshrayas/blogs/blob/eb7c98e2c088e70bf69c1e31abc1f643f9cd7dfb/ebpf/01-intro-ebpf-rust/code/syscall-tracer/src/bpf/syscall.bpf.c#L7)

```c
// Send data to userspace
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

```

**Ring Buffers** - Modern alternative to perf events (Linux 5.8+)
- Lower overhead, better memory efficiency
- Built-in backpressure handling

### Map Usage Patterns:
- **Counters**: Track metrics (packets, syscalls, errors)
- **Caching**: Store lookup results to avoid repeated work  
- **State machines**: Track connection states, user sessions
- **Configuration**: Runtime configuration from userspace

## 4. Helper Functions: Kernel API

eBPF programs can't directly call kernel functions. Instead, they use **helper functions** - a curated set of safe kernel APIs.

### Common Helper Categories:

#### Debugging & Logging
```c

bpf_printk("PID %d called syscall %d\n", pid, syscall_nr);

```

#### Map Operations

```c
// reading from the map
void *value = bpf_map_lookup_elem(&my_map, &key);
// updating/inserting into map
bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);
// delete the Key/Value from map
bpf_map_delete_elem(&my_map, &key);
```

#### Context Information
```c
// This is to get the Pid and Tid of a process
// Usage: We did use this helper function to read the pid from kernel in the previous blog
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;

```

#### Network Operations
```c
// Redirect packet to another interface
bpf_redirect(ifindex, 0);

// Modify packet data
bpf_skb_store_bytes(skb, offset, data, len, 0);
```

#### Time & Random
```c
u64 timestamp = bpf_ktime_get_ns();
u32 random = bpf_get_prandom_u32();
```
*Usage of helper function depends on the eBPF program types.

## 5. BTF & CO-RE: Write Once, Run Everywhere

**BTF (BPF Type Format)** and **CO-RE (Compile Once, Run Everywhere)** solve the kernel compatibility problem.

### The Problem:
Kernel structures change between versions:
```c
// Kernel 5.4
struct task_struct {
    int pid;
    char comm[16];
    // ... other fields
};

// Kernel 5.10 - field moved!
struct task_struct {
    char comm[16];  
    int pid;        // Different offset!
    // ... other fields  
};
```

### The Solution - CO-RE:

We briefly introduced this in the previous post. Now, let’s explore how CO-RE works and why it's crucial for building portable eBPF programs.

CO-RE leverages BTF (BPF Type Format) to make eBPF programs kernel-version aware at runtime, without recompiling for each kernel.

```c
#include "vmlinux.h"  // Generated BTF types

struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// CO-RE automatically adjusts field offsets at load time!
int pid = BPF_CORE_READ(task, pid);
```
Here’s what’s happening:

* vmlinux.h contains type definitions extracted from the kernel using BTF.

* BPF_CORE_READ() safely reads the pid field from task_struct, regardless of its offset.

* When you load the eBPF program, libbpf compares compiled offsets with the actual kernel’s layout and relocates field access as needed.

**Benefits:**
- Compile once, run on any kernel version
- Automatic field offset relocation
- Runtime kernel adaptation

This is why `build.rs` includes `vmlinux` - it provides BTF types for the target kernel!

## 6. BPF Tail Calls: Program Chaining

**Tail calls** allow one eBPF program to call another, enabling:
- Complex logic across multiple programs
- Runtime program updates
- Modular architectures

```c
// Program array map
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

// Tail call to another program
bpf_tail_call(ctx, &programs, program_index);
// This program ends here - control transfers completely
```

**Use Cases:**
- Packet processing pipelines
- Protocol parsers (HTTP → TCP → IP)
- Feature toggles (enable/disable functionality)

## 7. BPF Token: Delegated Privileges

**BPF Token** enables **secure eBPF in containers** by allowing privilege delegation.

### The Problem:
eBPF traditionally requires `CAP_BPF` or `CAP_SYS_ADMIN`, which gives too many privileges for containers.

### The Solution:
```bash
# Privileged process (container runtime) creates token
bpftool token create /sys/fs/bpf/token delegate_cmds prog_load,map_create

# Unprivileged container uses token
bpf_prog_load_token(prog_fd, token_fd, ...)
```

**Benefits:**
- Containers can run eBPF without root
- Fine-grained permission control  
- Better security isolation

*Note: BPF Token is available starting Linux 6.7. See kernel docs for full usage.*

## 8. eBPF Tools Ecosystem

### **bpftool** - The Swiss Army Knife
```bash
# List all programs
bpftool prog list

# Show program details
bpftool prog show id 123

# Dump program bytecode
bpftool prog dump xlated id 123

# Pin programs to filesystem
bpftool prog pin id 123 /sys/fs/bpf/my_prog
```

### **bpftrace** - Dynamic Tracing Scripts
```bash
# Trace file opens
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s opened %s\n", comm, str(args->filename)); }'

# Network packet counting
bpftrace -e 'kprobe:dev_queue_xmit { @packets[comm] = count(); }'
```

### **BCC** - Python eBPF Framework
- Higher-level Python interface
- Great for prototyping and learning
- Compiles C code at runtime

*Rust/libbpf-rs approach which we discussed in the previous blog, is more modern and performant than BCC!*

## Putting It All Together

Here's how these components work in syscall tracer which is demostrated in the previous blog:

1. **Program Type**: Tracepoint (`sys_enter_*`)
2. **Hook Point**: Syscall entry points
3. **Verifier**: Validated the program safety
4. **Maps**: Perf event array for data streaming
5. **Helper Functions**: `bpf_get_current_pid_tgid()`, `bpf_perf_event_output()`
6. **BTF/CO-RE**: Automatic kernel compatibility
7. **Tools**: `bpftool` for debugging, Rust for userspace

## Next Steps

With a solid understanding of eBPF’s foundational building blocks, you’re now ready to go beyond theory and start building powerful, production-grade tools.

In upcoming posts, we’ll use these primitives to implement practical, real-world applications—tapping into different eBPF program types and kernel hook points. While we won’t spoil what’s next, expect deep dives into applied observability, security, and networking powered by eBPF and Rust.

To explore more in the meantime:

* [Introduction to eBPF](https://ebpf.io/what-is-ebpf/#introduction-to-ebpf) – Learn the concepts behind the technology

* [eBPF Documentation Hub](https://docs.ebpf.io/) – Official docs, tutorials, and developer guides