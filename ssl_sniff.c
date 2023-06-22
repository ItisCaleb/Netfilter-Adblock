#include <assert.h>
#include <regex.h>
#include <stdio.h>
#include "ssl_sniff.skel.h"


#define BUF_MAX_LEN 256
struct data_t {
    unsigned int pid;
    int len;
    unsigned char buf[BUF_MAX_LEN];
};

regex_t preg;

void handle_sniff(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct data_t *d = data;
    printf("%s", d->buf);
    if (d->buf[0] == 'G' && d->buf[1] == 'E' && d->buf[2] == 'T') {
        int r = regexec(&preg, d->buf, 0, NULL, 0);
        if (!r) {
            printf("match!!\n");
        }
    }
    fflush(stdout);
}


int main()
{
    int ret = regcomp(&preg, "/a/?ad=", REG_NOSUB);
    assert(ret == 0);

    struct ssl_sniff_bpf *skel;
    struct perf_buffer *pb = NULL;
    skel = ssl_sniff_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    struct bpf_uprobe_opts ops = {
        .sz = sizeof(struct bpf_uprobe_opts),
        .func_name = "SSL_write",
        .ref_ctr_offset = 0x6,
        .retprobe = false,
    };
    bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_write, -1,
                                    "libssl.so.3", 0, &ops);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.tls_event), 8, &handle_sniff,
                          NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 0;
    }
    while (1) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
    return 0;
}