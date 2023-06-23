#include "send_close.h"
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/netfilter_bridge.h>
#include <net/ip.h>
#include <net/tcp.h>

static void send_tcp(struct sk_buff *nskb,
                     struct sk_buff *oskb,
                     struct tcphdr *tcph,
                     struct iphdr *niph,
                     const struct nf_hook_state *state)
{
    tcph->check =
        ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr, niph->daddr, 0);
    nskb->ip_summed = CHECKSUM_PARTIAL;
    nskb->csum_start = (unsigned char *) tcph - nskb->head;
    nskb->csum_offset = offsetof(struct tcphdr, check);

    /* ip_route_me_harder expects skb->dst to be set */
    skb_dst_set_noref(nskb, skb_dst(oskb));

    if (ip_route_me_harder(state->net, nskb->sk, nskb, RTN_UNSPEC))
        goto free_nskb;


    /* "Never happens" */
    if (nskb->len > dst_mtu(skb_dst(nskb)))
        goto free_nskb;

    ip_local_out(state->net, nskb->sk, nskb);
    return;
free_nskb:
    kfree_skb(nskb);
}

static struct iphdr *build_ip(struct net *net,
                              struct sk_buff *skb,
                              u32 saddr,
                              u32 daddr,
                              int ttl)
{
    struct iphdr *iph;
    skb_reset_network_header(skb);
    iph = skb_put(skb, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) / 4;
    iph->tos = 0;
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr;
    iph->ttl = ttl;

    skb->protocol = htons(ETH_P_IP);

    return iph;
}


void send_client_ack(struct sk_buff *oldskb, const struct nf_hook_state *state)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    oth =
        skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_otcph), &_otcph);

    oiph = ip_hdr(oldskb);

    nskb =
        alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) + MAX_TCP_HEADER,
                  GFP_ATOMIC);
    if (!nskb)
        return;

    nskb->mark = IP4_REPLY_MARK(state->net, oldskb->mark);

    skb_reserve(nskb, MAX_TCP_HEADER);
    niph = build_ip(state->net, nskb, oiph->daddr, oiph->saddr,
                    ip4_dst_hoplimit(skb_dst(oldskb)));

    skb_reset_transport_header(nskb);
    tcph = skb_put(nskb, sizeof(struct tcphdr));
    tcph->source = oth->dest;
    tcph->dest = oth->source;
    tcph->seq = htonl(ntohl(oth->ack_seq) + 1);
    tcph->ack_seq = oth->ack_seq;
    tcp_flag_word(tcph) = TCP_FLAG_ACK;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->window = htons(ntohs(oth->window));
    tcph->check = 0;
    tcph->urg_ptr = 0;

    send_tcp(nskb, oldskb, tcph, niph, state);
}

void send_close(struct sk_buff *oldskb,
                const struct Protocol *proto,
                const struct nf_hook_state *state)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    oth =
        skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_otcph), &_otcph);

    oiph = ip_hdr(oldskb);

    nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
                         proto->abort_message_len + LL_MAX_HEADER,
                     GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    niph = build_ip(state->net, nskb, oiph->daddr, oiph->saddr,
                    ip4_dst_hoplimit(skb_dst(oldskb)));

    skb_reset_transport_header(nskb);
    tcph = (struct tcphdr *) skb_put(nskb, sizeof(struct tcphdr));
    tcph->source = oth->dest;
    tcph->dest = oth->source;
    tcph->seq = htonl(ntohl(oth->ack_seq) + 1);
    tcph->ack_seq = oth->ack_seq;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcp_flag_word(tcph) |= TCP_FLAG_ACK | TCP_FLAG_RST;
    tcph->window = htons(ntohs(oth->window));
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // add response
    memcpy(skb_put(nskb, proto->abort_message_len), proto->abort_message,
           proto->abort_message_len);

    send_tcp(nskb, oldskb, tcph, niph, state);
}

void send_fin(struct sk_buff *oldskb, const struct nf_hook_state *state)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    oth =
        skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_otcph), &_otcph);
    if (oth == NULL)
        return;

    if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        return;

    oiph = ip_hdr(oldskb);

    nskb =
        alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_MAX_HEADER,
                  GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    niph = build_ip(state->net, nskb, oiph->saddr, oiph->daddr,
                    ip4_dst_hoplimit(skb_dst(oldskb)));

    skb_reset_transport_header(nskb);
    tcph = (struct tcphdr *) skb_put(nskb, sizeof(struct tcphdr));
    tcph->source = oth->source;
    tcph->dest = oth->dest;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->seq = oth->seq;
    tcph->ack_seq = oth->ack_seq;
    tcp_flag_word(tcph) |= TCP_FLAG_ACK | TCP_FLAG_FIN;
    tcph->window = htons(ntohs(oth->window));
    tcph->check = 0;
    tcph->urg_ptr = 0;

    send_tcp(nskb, oldskb, tcph, niph, state);
}

void send_server_reset(struct sk_buff *oldskb,
                       const struct nf_hook_state *state)
{
    struct sk_buff *nskb;
    const struct iphdr *oiph;
    struct iphdr *niph;
    const struct tcphdr *oth;
    struct tcphdr _otcph, *tcph;

    /* IP header checks: fragment. */
    if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
        return;

    oth =
        skb_header_pointer(oldskb, ip_hdrlen(oldskb), sizeof(_otcph), &_otcph);
    if (oth == NULL)
        return;

    /* No RST for RST. */
    if (oth->rst)
        return;

    if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        return;

    /* Check checksum */
    if (nf_ip_checksum(oldskb, state->hook, ip_hdrlen(oldskb), IPPROTO_TCP))
        return;
    oiph = ip_hdr(oldskb);

    nskb =
        alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_MAX_HEADER,
                  GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    niph = build_ip(state->net, nskb, oiph->saddr, oiph->daddr,
                    ip4_dst_hoplimit(skb_dst(oldskb)));

    skb_reset_transport_header(nskb);
    tcph = (struct tcphdr *) skb_put(nskb, sizeof(struct tcphdr));
    tcph->source = oth->source;
    tcph->dest = oth->dest;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->seq = oth->seq;
    tcph->ack_seq = oth->ack_seq;
    tcp_flag_word(tcph) |= TCP_FLAG_ACK | TCP_FLAG_RST;
    tcph->window = htons(ntohs(oth->window));
    tcph->check = 0;
    tcph->urg_ptr = 0;

    send_tcp(nskb, oldskb, tcph, niph, state);
}
