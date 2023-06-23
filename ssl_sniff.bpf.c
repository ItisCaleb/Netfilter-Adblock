#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tls_event SEC(".maps");

#define BUF_MAX_LEN 256
struct data_t {
    unsigned int pid;
    int len;
    unsigned char buf[BUF_MAX_LEN];
};

SEC("uprobe")
int BPF_KPROBE(probe_SSL_write, void *ssl, char *buf, int num)
{
    unsigned long long current_pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = current_pid_tgid >> 32;
    int len = num;
    if (len < 0)
        return 0;

    unsigned int kZero = 0;
    struct data_t data;
    data.pid = pid;
    data.len = (len < BUF_MAX_LEN ? (len & BUF_MAX_LEN - 1) : BUF_MAX_LEN);
    bpf_probe_read_user(data.buf, data.len, buf);
    bpf_perf_event_output(ctx, &tls_event, BPF_F_CURRENT_CPU, &data,
                          sizeof(struct data_t));

    return 0;
}

char _license[] SEC("license") = "GPL";