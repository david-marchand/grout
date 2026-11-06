// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define GR_CKSUM_IP_BAD RTE_MBUF_F_RX_IP_CKSUM_BAD
#define GR_CKSUM_IP_GOOD RTE_MBUF_F_RX_IP_CKSUM_GOOD
#define GR_CKSUM_IP_MASK (GR_CKSUM_IP_BAD | GR_CKSUM_IP_GOOD)

#define GR_CKSUM_L4_BAD RTE_MBUF_F_RX_L4_CKSUM_BAD
#define GR_CKSUM_L4_GOOD RTE_MBUF_F_RX_L4_CKSUM_GOOD
#define GR_CKSUM_L4_MASK (GR_CKSUM_L4_BAD | GR_CKSUM_L4_GOOD)

#define GR_CKSUM_MASK (GR_CKSUM_IP_MASK | GR_CKSUM_L4_MASK)

static inline bool gr_cksum_ip_good(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_IP_MASK) == GR_CKSUM_IP_GOOD;
}

static inline bool gr_cksum_ip_bad(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_IP_MASK) == GR_CKSUM_IP_BAD;
}

static inline bool gr_cksum_ip_unknown(const struct rte_mbuf *m) {
	return !(m->ol_flags & GR_CKSUM_IP_MASK);
}

static inline bool gr_cksum_ip_valid(const struct rte_mbuf *m) {
	return !!(m->ol_flags & GR_CKSUM_IP_GOOD);
}

static inline void gr_cksum_ip_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_IP_BAD;
	m->ol_flags |= GR_CKSUM_IP_GOOD;
}

static inline void gr_cksum_ip_set_unknown(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_IP_MASK;
}

static inline bool gr_cksum_l4_good(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_GOOD;
}

static inline bool gr_cksum_l4_bad(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_BAD;
}

static inline bool gr_cksum_l4_partial(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_MASK;
}

static inline bool gr_cksum_l4_unknown(const struct rte_mbuf *m) {
	return !(m->ol_flags & GR_CKSUM_L4_MASK);
}

static inline bool gr_cksum_l4_valid(const struct rte_mbuf *m) {
	return !!(m->ol_flags & GR_CKSUM_L4_GOOD);
}

static inline void gr_cksum_l4_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_L4_BAD;
	m->ol_flags |= GR_CKSUM_L4_GOOD;
}

static inline void gr_cksum_l4_set_partial(struct rte_mbuf *m) {
	m->ol_flags |= GR_CKSUM_L4_MASK;
}

static inline void gr_cksum_l4_set_unknown(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_L4_MASK;
}

static inline void gr_cksum_reset(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_MASK;
}

#define IS_IPV4(ihl) (((ihl) >> 4) == IPVERSION)

static inline void gr_cksum_resolve(struct rte_mbuf *m, uint64_t tx_offloads) {
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip4;

	if (!gr_cksum_l4_partial(m))
		return;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);

		ip4 = (struct rte_ipv4_hdr *)(vlan + 1);
	} else {
		ip4 = (struct rte_ipv4_hdr *)(eth + 1);
	}

	if (IS_IPV4(ip4->version_ihl)) {
		if (ip4->next_proto_id == IPPROTO_UDP) {
			struct rte_udp_hdr
				*udp = (struct rte_udp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
				m->l2_len = (char *)ip4 - (char *)eth;
				m->l3_len = (char *)udp - (char *)ip4;
				m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
				udp->dgram_cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
			} else {
				udp->dgram_cksum = 0;
				udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip4, udp);
			}
		} else if (ip4->next_proto_id == IPPROTO_TCP) {
			struct rte_tcp_hdr
				*tcp = (struct rte_tcp_hdr *)((char *)ip4 + rte_ipv4_hdr_len(ip4));

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip4 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip4;
				m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM;
				tcp->cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv4_udptcp_cksum(ip4, tcp);
			}
		}
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;

		if (ip6->proto == IPPROTO_UDP) {
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip6 + 1);

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
				m->l2_len = (char *)ip6 - (char *)eth;
				m->l3_len = (char *)udp - (char *)ip6;
				m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
				udp->dgram_cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				udp->dgram_cksum = 0;
				udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip6, udp);
			}
		} else if (ip6->proto == IPPROTO_TCP) {
			struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip6 + 1);

			if (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
				m->l2_len = (char *)ip6 - (char *)eth;
				m->l3_len = (char *)tcp - (char *)ip6;
				m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM;
				tcp->cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
			}
		}
	}

	gr_cksum_l4_set_good(m);
}
