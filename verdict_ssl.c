#include "verdict_ssl.h"
#include <linux/mutex.h>
#include <linux/slab.h>

struct list_head order_head, verdict_head;
static DEFINE_MUTEX(insert_mutex);

void init_verdict(void)
{
    INIT_LIST_HEAD(&order_head);
    INIT_LIST_HEAD(&verdict_head);
}


struct queue_st *insert_order(ktime_t timestamp)
{
    int ret = mutex_trylock(&insert_mutex);
    if (ret != 0) {
        struct list_head *cur;
        struct queue_st *order;
        list_for_each (cur, &order_head) {
            order = list_entry(cur, struct queue_st, head);
            if (order->timestamp < timestamp)
                break;
        }
        order = kmalloc(sizeof(struct queue_st), GFP_KERNEL);
        order->timestamp = timestamp;
        list_add(&order->head, cur);
        mutex_unlock(&insert_mutex);
        return order;
    }
    return NULL;
}


/*
    Verdict result is store at LSB of pid
    0 for pass
    1 for block
*/
void insert_verdict(pid_t pid)
{
    struct queue_st *verdict;
    verdict = kmalloc(sizeof(struct queue_st), GFP_KERNEL);
    verdict->pid = pid;
    list_add_tail(&verdict->head, &verdict_head);
}

int poll_verdict(ktime_t timestamp, pid_t pid)
{
    struct queue_st *verdict, *first;
    int ret = -1;

    if (list_empty(&order_head) || list_empty(&verdict_head))
        return -1;
    first = list_first_entry(&order_head, struct queue_st, head);
    if (!first || first->timestamp != timestamp)
        return -1;

    list_for_each_entry (verdict, &verdict_head, head) {
        pid_t cpid = verdict->pid & ((1U << 31) - 1);
        int result = (u32) verdict->pid >> 31;
        if (cpid == pid) {
            ret = result;
            break;
        }
    }
    list_del(&verdict->head);
    list_del(&first->head);
    kfree(verdict);
    kfree(first);
    return ret;
}