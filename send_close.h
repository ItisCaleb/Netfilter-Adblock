#include "protocol.h"

struct nf_hook_state;
struct sk_buff;
void send_close(struct sk_buff *,
                const struct Protocol *,
                const struct nf_hook_state *);
void send_client_ack(struct sk_buff *, const struct nf_hook_state *);
void send_server_reset(struct sk_buff *, const struct nf_hook_state *);
void send_fin(struct sk_buff *, const struct nf_hook_state *);