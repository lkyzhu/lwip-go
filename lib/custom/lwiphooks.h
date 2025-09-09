
#ifndef LWIP_GO_HOOKS_H
#define LWIP_GO_HOOKS_H

#include "lwip/pbuf.h"
extern err_t ip4_input_hook(struct pbuf *pbuf, struct netif *input_netif);

#if LWIP_IPV6
extern err_t ip6_input_hook(struct pbuf *pbuf, struct netif *input_netif);
#endif // LWIP_IPV6

#endif // LWIP-GO_HOOKS_H
