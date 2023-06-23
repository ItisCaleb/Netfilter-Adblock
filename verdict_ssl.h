#ifndef VERDICT_SSL_H
#define VERDICT_SSL_H
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/ktime.h>

struct queue_st {
    struct list_head head;
    union {
        ktime_t timestamp;
        pid_t pid;
    };
};

void init_verdict(void);

struct queue_st *insert_order(ktime_t timestamp);

void insert_verdict(pid_t pid);


/*
    return value:
    -1: Queue is empty or not ready
    0 : Let request pass
    1 : Block this request
*/
int poll_verdict(ktime_t timestamp, pid_t pid);

#endif