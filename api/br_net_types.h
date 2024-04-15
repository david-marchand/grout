// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_NET_TYPES
#define _BR_NET_TYPES

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_ADDR_RE "^[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}$"
#define ETH_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_SCAN "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c"
#define ETH_BYTES_SPLIT(b) b[0], b[1], b[2], b[3], b[4], b[5]

struct eth_addr {
	uint8_t bytes[6];
};

static inline void br_eth_addr_broadcast(struct eth_addr *mac) {
	memset(mac->bytes, 0xff, sizeof(mac->bytes));
}

static inline int br_eth_addr_parse(const char *s, struct eth_addr *mac) {
	int ret = sscanf(
		s,
		ETH_ADDR_SCAN,
		&mac->bytes[0],
		&mac->bytes[1],
		&mac->bytes[2],
		&mac->bytes[3],
		&mac->bytes[4],
		&mac->bytes[5]
	);
	return ret == 6 ? 0 : -1;
}

#define IPV4_ATOM "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
#define IPV4_RE "^" IPV4_ATOM "(\\." IPV4_ATOM "){3}$"
#define IPV4_NET_RE "^" IPV4_ATOM "(\\." IPV4_ATOM "){3}/(3[0-2]|[12][0-9]|[0-9])$"

typedef uint32_t ip4_addr_t;

struct ip4_net {
	ip4_addr_t ip;
	uint8_t prefixlen;
};

static inline int br_ip4_net_parse(const char *s, struct ip4_net *net, bool zero_mask) {
	char *addr = NULL;
	int ret = -1;

	if (sscanf(s, "%m[0-9.]/%hhu%*c", &addr, &net->prefixlen) != 2) {
		errno = EINVAL;
		goto out;
	}
	if (net->prefixlen > 32) {
		errno = EINVAL;
		goto out;
	}
	if (inet_pton(AF_INET, addr, &net->ip) != 1) {
		errno = EINVAL;
		goto out;
	}
	if (zero_mask) {
		// mask non network bits to zero
		net->ip &= htonl((uint32_t)(UINT64_MAX << (32 - net->prefixlen)));
	}
	ret = 0;
out:
	free(addr);
	return ret;
}

static inline int br_ip4_net_format(const struct ip4_net *net, char *buf, size_t len) {
	const char *tmp;
	int n;

	if ((tmp = inet_ntop(AF_INET, &net->ip, buf, len)) == NULL)
		return -1;
	n = strlen(tmp);
	return snprintf(buf + n, len - n, "/%u", net->prefixlen);
}

#endif