#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>


#include "tls.h"
#include "http.h"
#include "dns.h"
#include "send_close.h"
#include "host_table.h"

static void *my_skb_header_pointer(struct sk_buff *skb, size_t data_off, size_t data_len, bool *should_free)
{
    char *data = NULL;

    *should_free = false;

    if (skb_headlen(skb) >= data_off + data_len)
    {
        return skb->data + data_off;
    }
    else
    {
        data = kmalloc(data_len, GFP_KERNEL);
        if (!data)
        {
            return NULL;
        }

        if (skb_copy_bits(skb, data_off, data, data_len) < 0)
        {
            kfree(data);
            return NULL;
        }
        *should_free = true;

        return data;
    }
}

/*
    Extract TCP data from sk_buff
    
    return data length if such data exist
    else return -1
*/
static int extract_tcp_data(struct sk_buff *skb, char **data, bool *should_free){
    struct iphdr *ip = NULL;
    struct tcphdr  *tcp = NULL;
    size_t data_off, data_len;

    if (!skb || !(ip = ip_hdr(skb)) || IPPROTO_TCP != ip->protocol)
        return -1; // not ip - tcp

    if (!(tcp = tcp_hdr(skb)))
        return -1; // bad tcp
    
    /* data length = total length - ip header length - tcp header length */
    data_off = ip->ihl * 4 + tcp->doff * 4;
    data_len = skb->len - data_off;

    if(data_len == 0)
        return -1;

    *data = my_skb_header_pointer(skb, data_off, data_len, should_free);

    return data_len;
}

static int extract_udp_data(struct sk_buff *skb, char **data, bool *should_free){
    struct iphdr *ip = NULL;
    struct udphdr  *udp = NULL;
    size_t data_off, data_len;

    if (!skb || !(ip = ip_hdr(skb)) || IPPROTO_UDP != ip->protocol)
        return -1; // not ip - udp

    if (!(udp = udp_hdr(skb)))
        return -1; // bad udp
    
    /* data length = total length - ip header length - udp header length */
    data_off = ip->ihl * 4 + sizeof(struct udphdr);
    data_len = skb->len - data_off;

    if(data_len == 0)
        return -1;

    *data = my_skb_header_pointer(skb, data_off, data_len, should_free);

    return data_len;
}

static unsigned int blocker_hook(void *priv, struct sk_buff *skb,
 const struct nf_hook_state *state)
{
    int ret = NF_ACCEPT;
    
    char *data = NULL;
    char *host = NULL;
    bool should_free = false;
    const char *flag;
    const struct Protocol *proto = NULL;
    int tcpflag = 0;


    /*
        Extract TCP data
    */
    int len = extract_tcp_data(skb, &data, &should_free);
    if(len != -1){
        tcpflag = 1;
        if(data[0] == 0x16){
            printk("TLS handshake len: %d",len);
            proto = tls_protocol;
        }else if(strncmp(data, "GET ", sizeof("GET ")-1) == 0){
            proto = http_protocol;
        }
    }
    len = extract_udp_data(skb, &data, &should_free);
    if(len != -1){
        if(ntohs(udp_hdr(skb)->dest) == 53){
            proto = dns_protocol;
        }
    }

    /*
        Extract host from data
    */
    if(proto)
        proto->parse_packet(data, len, &host);
    
    /*
        Drop packet if host is within block list
    */
    if(host){
        printk("Host: %s",host);
        flag = in_word_set(host, strlen(host));
        if (flag){
            printk("Dropping Packet");
            ret = NF_DROP;
            if(tcpflag){
                send_server_ack(skb,state);
                send_close(skb, proto, state);
                send_tcp_reset(skb, state);
            }
        }
        kfree(host);
    }
    if(should_free)
        kfree(data);

    return ret;
}
static struct nf_hook_ops blocker_ops = {
    .hook = blocker_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT
};

static int mod_init(void)
{
    return nf_register_net_hook(&init_net,&blocker_ops);
}

static void mod_exit(void)
{
    nf_unregister_net_hook(&init_net,&blocker_ops);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("Dual MIT/GPL");
