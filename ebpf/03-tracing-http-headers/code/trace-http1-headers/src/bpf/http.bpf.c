#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_HTTP_DATA_LEN 256 // Max bytes to capture from request/response
#define MAX_HTTP_PATH_LEN 128 // Max bytes for HTTP path

struct event_t
{
    u32 pid;
    u8 is_request;
    u32 data_len;
    char data[MAX_HTTP_DATA_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} http_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Adjust as needed
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} active_app_sockets SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);              // Max namespaces to track
    __uint(key_size, sizeof(__u32));        // Namespace inode number
    __uint(value_size, sizeof(__u8));       // Just a flag (1 = tracked)
} tracked_pids SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} read_args_map SEC(".maps");


static __always_inline int is_http_data(char *data, size_t len)
{
    if (len < 4)
        return 0;

    // Check for HTTP request methods
    if ((len >= 3 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
        (len >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') ||
        (len >= 3 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') ||
        (len >= 6 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E'))
    {
        return 1; // HTTP request
    }

    // Check for HTTP response
    if (len >= 8 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/')
    {
        return 2; // HTTP response
    }
    return 0;
}

static __always_inline int is_tracked_pids(u32 pid) {
    __u8 *tracked  = bpf_map_lookup_elem(&tracked_pids, &pid);
    return tracked ? 1 : 0;
}

SEC("kretprobe/__sys_accept4")
int handle_accept4_ret(struct pt_regs *ctx)
{
    int new_fd = PT_REGS_RC(ctx);
    if (new_fd < 0)
        return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (is_tracked_pids(pid)) {
        int one = 1;
        bpf_map_update_elem(&active_app_sockets, &new_fd, &one, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/ksys_read")
int kprobe_ksys_read_entry(struct pt_regs *ctx)
{
    int fd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);

    int *exists = bpf_map_lookup_elem(&active_app_sockets, &fd);
    if (!exists)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 addr = (u64)buf;

    bpf_map_update_elem(&read_args_map, &pid_tgid, &addr, BPF_ANY);
    return 0;
}

SEC("kretprobe/ksys_read")
int kretprobe_ksys_read_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 *buf_addr_ptr = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!buf_addr_ptr)
        return 0;

    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    char *buf = (char *)*buf_addr_ptr;
    long bytes_read = PT_REGS_RC(ctx);
    if (bytes_read <= 0)
        return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.is_request = 1;

    size_t data_len = bytes_read < MAX_HTTP_DATA_LEN ? bytes_read : MAX_HTTP_DATA_LEN;
    if (bpf_probe_read_user(evt.data, data_len, buf) != 0)
        return 0;

    int http_type = is_http_data(evt.data, data_len);
    if (http_type == 0)
        return 0;

    if (is_tracked_pids(pid)) {
        evt.data_len = data_len;

        bpf_perf_event_output(ctx, &http_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}

SEC("kprobe/__x64_sys_close")
int kprobe_ksys_close(struct pt_regs *ctx)
{
    int fd = PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&active_app_sockets, &fd);
    return 0;
}