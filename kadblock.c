#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/glob.h>

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/device.h>

#include "dns.h"
#include "host_table.h"
#include "send_close.h"
#include "verdict_ssl.h"

static atomic_t device_opened = ATOMIC_INIT(0);

/*
    Extract TCP data from sk_buff

    return data length if such data exist
    else return -1
*/
static int extract_tcp_data(struct sk_buff *skb, char **data)
{
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    size_t data_off, data_len;

    if (!skb || !(ip = ip_hdr(skb)) || IPPROTO_TCP != ip->protocol)
        return -1;  // not ip - tcp

    if (!(tcp = tcp_hdr(skb)))
        return -1;  // bad tcp

    /* data length = total length - ip header length - tcp header length */
    data_off = ip->ihl * 4 + tcp->doff * 4;
    data_len = skb->len - data_off;

    if (data_len == 0)
        return -1;

    if (skb_linearize(skb))
        return -1;

    *data = skb->data + data_off;

    return data_len;
}

/*
    Extract UDP data from sk_buff

    return data length if such data exist
    else return -1
*/
static int extract_udp_data(struct sk_buff *skb, char **data)
{
    struct iphdr *ip = NULL;
    struct udphdr *udp = NULL;
    size_t data_off, data_len;

    if (!skb || !(ip = ip_hdr(skb)) || IPPROTO_UDP != ip->protocol)
        return -1;  // not ip - udp

    if (!(udp = udp_hdr(skb)))
        return -1;  // bad udp

    /* data length = total length - ip header length - udp header length */
    data_off = ip->ihl * 4 + sizeof(struct udphdr);
    data_len = skb->len - data_off;

    if (skb_linearize(skb))
        return -1;

    *data = skb->data + data_off;

    return data_len;
}


static unsigned int blocker_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    char *data = NULL;
    char *host = NULL;
    int result = 0;

    /*
        Extract TCP data
    */
    int len = extract_tcp_data(skb, &data);
    if (len > 0) {
        /*  We use user space program to handle TLS.
            If the program isn't opening the device,
            then we just let the packet go through.
        */
        if (atomic_read(&device_opened) && data[0] == 0x17) {
            /*  TLS application */
            ktime_t time = ktime_get();
            struct queue_st *order = insert_order(time);
            result = -1;

            while (result == -1 &&
                   ktime_to_ms(ktime_sub(ktime_get(), time)) < 50) {
                result = poll_verdict(time, current->pid);
            }
            if (result == -1) {
                list_del(&order->head);
                kfree(order);
            }
        } else if (strncmp(data, "GET ", sizeof("GET ") - 1) == 0) {
            /* HTTP */
            result = glob_match("*ad[bcfgklnpqstwxyz_.=?-]*", data + 4);
        }
        if (result > 0) {
            send_server_reset(skb, state);
            return NF_DROP;
        }
    }

    /*
        Extract UDP data
    */
    len = extract_udp_data(skb, &data);
    if (len > 0) {
        if (ntohs(udp_hdr(skb)->dest) == 53) {
            /*
                Extract host from data
            */
            dns_protocol->parse_packet(data, len, &host);
            /*
                Drop packet if host is within block list
            */
            if (host) {
                result = in_word_set(host, strlen(host)) ? 1 : 0;
            }
            kfree(host);
        }
    }
    if (result > 0)
        return NF_DROP;

    return NF_ACCEPT;
}
static struct nf_hook_ops blocker_ops = {.hook = blocker_hook,
                                         .pf = NFPROTO_IPV4,
                                         .hooknum = NF_INET_LOCAL_OUT};

static int adbdev_open(struct inode *inode, struct file *file)
{
    if (atomic_cmpxchg(&device_opened, 0, 1))
        return -EBUSY;

    return 0;
}

static int adbdev_release(struct inode *inode, struct file *file)
{
    atomic_set(&device_opened, 0);

    return 0;
}

static loff_t adbdev_lseek(struct file *file, loff_t offset, int orig)
{
    pid_t pid = offset;
    insert_verdict(pid);
    return 0;
}


static struct file_operations fops = {.owner = THIS_MODULE,
                                      .open = adbdev_open,
                                      .release = adbdev_release,
                                      .llseek = adbdev_lseek};

#define DEV_NAME "adbdev"

static struct class *cls;
static int major;

static int mod_init(void)
{
    major = register_chrdev(0, DEV_NAME, &fops);
    if (major < 0) {
        pr_alert("Registering char device failed with %d\n", major);
        return major;
    }
    cls = class_create(THIS_MODULE, DEV_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEV_NAME);

    init_verdict();
    return nf_register_net_hook(&init_net, &blocker_ops);
}

static void mod_exit(void)
{
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, DEV_NAME);
    nf_unregister_net_hook(&init_net, &blocker_ops);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
