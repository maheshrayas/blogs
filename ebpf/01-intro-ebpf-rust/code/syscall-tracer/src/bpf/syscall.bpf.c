#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} syscall_events SEC(".maps");

struct data_t {
    __u64 pid;      
    __u64 sysnbr;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.sysnbr = ctx->id;
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
