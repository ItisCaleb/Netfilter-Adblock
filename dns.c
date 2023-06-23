#ifdef __KERNEL__
#include <linux/slab.h>
#define printf printk
#define free kfree
#define malloc(_SIZE) kmalloc(_SIZE, GFP_KERNEL)
#else
#include <stdint.h>
#include <stdlib.h> /* malloc() */
#include <string.h> /* strncpy() */
#include <sys/types.h>
#endif

#include "dns.h"

static int parse_host(const char *, size_t, char **);

const struct Protocol *const dns_protocol = &(struct Protocol){
    .name = "dns",
    .default_port = 53,
    .parse_packet = (int (*const)(const char *, size_t, char **)) & parse_host,
    .abort_message = 0,
    .abort_message_len = 0};

static int parse_host(const char *data, size_t data_len, char **hostname)
{
    int idx = 0;
    char *host;
    int qr;
    int count, len = 0;
    /*ID 2 bytes*/
    idx += 2;
    /*QR query=0 response=1*/
    qr = data[idx] >> 7;
    if (qr)
        return -1;
    /*
        header 12 bytes
        12 - 2 = 10
    */
    idx += 10;

    /* max domain name length + \0 */
    host = malloc(253 + 1);

    /*
        Extract host
        Format is a length octet
        followed by that number of octets
    */
    while ((count = data[idx++])) {
        if (len + count + 1 > 253) {
            free(host);
            return -1;
        }

        /*concat labels*/
        strncpy(host + len, data + idx, count);
        len += count + 1;
        host[len - 1] = '.';
        idx += count;
    }
    host[len - 1] = '\0';
    *hostname = host;
    return len;
}