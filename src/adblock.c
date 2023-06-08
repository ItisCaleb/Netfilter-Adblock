#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "host_table.h"
#include "tls.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

#define IPTYPE 8
#define TCPTYPE 6

typedef uint32_t tcp_seq;

u_int32_t id;

void iptables_F() { system("iptables -F"); }

void exit_sig(int sig) {
  printf("closing library handle\n");
  iptables_F();
  exit(0);
}

// ---------------------------------------------------------------
static u_int32_t parse_pkt(struct nfq_data *tb, char **host) {
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  int ret;
  unsigned char *data; // data for nfq_get_payload

  struct ip *ipHdr;
  struct tcphdr *tcpHdr;
  char *tcp_data_area;
  int ip_hdr_size;
  int tcp_hdr_size;
  int tcp_data_len;
  char *search_host;

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph)
    id = ntohl(ph->packet_id); // id

  int size = nfq_get_payload(tb, &data);
  // Get IP header
  
  ipHdr = (struct ip *)data;      // right
  ip_hdr_size = ipHdr->ip_hl * 4; // only ip header length

  // printf("[*] ipHdr size : %d\n", ip_hdr_size); // always 20 bytes

  // Get TCP header
  tcpHdr = (struct tcphdr *)(data + ip_hdr_size); // located at +20
  tcp_hdr_size = (tcpHdr->th_off * 4);            // tcp header size
  tcp_data_area = data + ip_hdr_size + tcp_hdr_size;
  tcp_data_len = ret - ip_hdr_size - tcp_hdr_size; // ret is total length

  if (ipHdr->ip_p == TCPTYPE && tcp_hdr_size > 0) {
    /*
        Get SNI from TLS extension
    */
    if (tcp_data_area[0] == 0x16) {
      tls_protocol->parse_packet(tcp_data_area, tcp_data_len, host);
    }
    /*
        Get Host from HTTP header
    */
    else if (strncmp(tcp_data_area, "GET", 3) == 0) {
      char *start = strstr(tcp_data_area, "Host: ") + 6;
      char *end = strstr(start, "\r\n");
      int len = end - start;
      *host = malloc(len + 1);
      strncpy(*host, start, len);
      (*host)[len] = '\0';
    }
  }

  return id;
}

static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data) {
  char *host = NULL;
  u_int32_t id = parse_pkt(nfa, &host);
  u_int8_t flag = 1;
  if (host != NULL) {
    printf("Host: %s\n", host);
    char *ret = in_word_set(host, strlen(host));
    if (ret)
      flag = 0;
    free(host);
  }
  return nfq_set_verdict(qh, id, flag, 0, NULL); // flag: 1 ACCEPT, 0 DROP
}

int main(int argc, char *argv[]) {
  struct nfq_handle *h; // struct nfnl_handle * 	nfnlh
                        // struct nfq_q_handle * 	qh_list
                        // struct nfnl_subsys_handle * 	nfnlssh
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__((aligned));

  signal(SIGINT, exit_sig);

  // Initializing the iptables configuration
  system("iptables -F"); // iptables_F
  system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
  system("iptables -A INPUT -j NFQUEUE --queue-num 0");

  printf("opening library handle\n");
  h = nfq_open(); // handler of a netfilter queue

  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    iptables_F();
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    iptables_F();
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    iptables_F();
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h, 0, &packet_handler, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    iptables_F();
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    iptables_F();
    exit(1);
  }

  fd = nfq_fd(h); // usage: nfq_fd(handler)

  for (;;) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {

      // printf("[+] pkt received\n");
      nfq_handle_packet(h, buf, rv);
      continue;
    }
    if (rv < 0 && errno == ENOBUFS) {
      printf("[-] losing packets!\n");
      continue;
    }
    perror("[-] recv failed");
    break;
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);
  iptables_F();
  exit(0);
}
