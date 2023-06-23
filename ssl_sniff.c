#include <assert.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "ssl_sniff.skel.h"


#define BUF_MAX_LEN 256
struct data_t {
    unsigned int pid;
    int len;
    char buf[BUF_MAX_LEN];
};

regex_t preg;
int fd;

void handle_sniff(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct data_t *d = data;
    uint32_t result = 0;
    if (d->buf[0] == 'G' && d->buf[1] == 'E' && d->buf[2] == 'T') {
        int r = regexec(&preg, d->buf, 0, NULL, 0);
        if (!r)
            result = 1;
    }
    lseek(fd, d->pid | result << 31, 0);
}

const char regexp[] = "[/_.?\\-]ad[bcfgklnpqstwxyz/_.=?\\-]";

int main(int argc, char *argv[])
{
    if (argc == 1 || !(argc & 1)) {
        printf("wrong argument count\n");
        printf("Usage: %s <libpath1> <func1> <libpath2> <func2>\n", argv[0]);
        exit(0);
    }

    int ret = regcomp(&preg, regexp, REG_NOSUB | REG_ICASE);
    assert(ret == 0);


    struct ssl_sniff_bpf *skel;
    struct perf_buffer *pb = NULL;
    skel = ssl_sniff_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    for (int i = 1; i < argc; i += 2) {
        printf("Attaching %s in %s\n", argv[i + 1], argv[i]);
        struct bpf_uprobe_opts *ops = malloc(sizeof(struct bpf_uprobe_opts));
        ops->sz = sizeof(*ops);
        ops->ref_ctr_offset = 0x6;
        ops->retprobe = false;
        ops->func_name = argv[i + 1];
        bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_write, -1,
                                        argv[i], 0, ops);
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.tls_event), 8, &handle_sniff,
                          NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 0;
    }

    printf("Opening adbdev...\n");
    fd = open("/dev/adbdev", O_WRONLY);
    if (fd < 0) {
        printf(
            "Failed to open adbdev.\nIt could be due to another program"
            "using it or the kernel module not being loaded.\n");
        exit(1);
    }

    printf("All ok. Sniffing plaintext now\n");
    while (1) {
        int err = perf_buffer__poll(pb, 1);
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
    return 0;
}