#ifdef __KERNEL__
#include <linux/slab.h>
#define printf printk
#define malloc(_SIZE) kmalloc(_SIZE, GFP_KERNEL)
#else
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <string.h> /* strncpy() */
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "http.h"

static char http_close[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text-html\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

static int parse_host(const char *, size_t, char **);

const struct Protocol *const http_protocol = &(struct Protocol){
    .name = "http",
    .default_port = 80,
    .parse_packet = (int (*const)(const char *, size_t, char **)) & parse_host,
    .abort_message = http_close,
    .abort_message_len = sizeof(http_close) - 1};

static int parse_host(const char *data, size_t data_len, char **hostname)
{
    char *start = strstr(data, "Host: ") + 6;
    char *end = strstr(start, "\r\n");
    int len = end - start;
    *hostname = malloc(len + 1);
    strncpy(*hostname, start, len);
    (*hostname)[len] = '\0';

    return len;
}