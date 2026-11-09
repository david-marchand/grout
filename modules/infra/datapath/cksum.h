// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#define GR_CKSUM_IP_BAD RTE_MBUF_F_RX_IP_CKSUM_BAD
#define GR_CKSUM_IP_GOOD RTE_MBUF_F_RX_IP_CKSUM_GOOD
#define GR_CKSUM_IP_MASK (GR_CKSUM_IP_BAD | GR_CKSUM_IP_GOOD)

#define GR_CKSUM_L4_BAD RTE_MBUF_F_RX_L4_CKSUM_BAD
#define GR_CKSUM_L4_GOOD RTE_MBUF_F_RX_L4_CKSUM_GOOD
#define GR_CKSUM_L4_MASK (GR_CKSUM_L4_BAD | GR_CKSUM_L4_GOOD)

// Repurpose unused DPDK outer IP checksum bit for inner L4 partial tracking.
#define GR_CKSUM_INNER_L4_PARTIAL RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD

#define GR_CKSUM_MASK (GR_CKSUM_IP_MASK | GR_CKSUM_L4_MASK | GR_CKSUM_INNER_L4_PARTIAL)

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

static inline bool gr_cksum_inner_l4_partial(const struct rte_mbuf *m) {
	return !!(m->ol_flags & GR_CKSUM_INNER_L4_PARTIAL);
}

static inline void gr_cksum_inner_l4_set_partial(struct rte_mbuf *m) {
	m->ol_flags |= GR_CKSUM_INNER_L4_PARTIAL;
}

static inline void gr_cksum_init(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_INNER_L4_PARTIAL;
}

static inline void gr_cksum_reset(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_MASK;
}

#define IS_IPV4(ihl) (((ihl) >> 4) == IPVERSION)

static inline uint16_t gr_cksum_update16(uint16_t old_cksum, uint16_t old_val, uint16_t new_val) {
	uint32_t sum = (~rte_be_to_cpu_16(old_cksum) & 0xffff)
		+ (~rte_be_to_cpu_16(old_val) & 0xffff) + rte_be_to_cpu_16(new_val);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return rte_cpu_to_be_16(~sum & 0xffff);
}

// Compute the outer UDP checksum from headers only, leveraging the fact
// that the inner L4 checksum already covers the payload (C + ~C = 0).
// Returns false if the inner L4 is not TCP/UDP or inner UDP has no checksum.
static inline bool vxlan_const_udp_cksum(struct rte_udp_hdr *udp, uint16_t outer_phdr_cksum) {
	struct rte_ether_hdr *inner_eth;
	struct rte_ipv6_hdr *inner_ip6;
	struct rte_ipv4_hdr *inner_ip4;
	struct rte_udp_hdr *inner_udp;
	uint16_t inner_phdr_cksum;
	void *inner_l4;
	uint32_t sum;

	inner_eth = (struct rte_ether_hdr *)((struct rte_vxlan_hdr *)(udp + 1) + 1);
	if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		inner_ip4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(inner_eth + 1) + 1);
	else
		inner_ip4 = (struct rte_ipv4_hdr *)(inner_eth + 1);

	if (IS_IPV4(inner_ip4->version_ihl)) {
		if (inner_ip4->next_proto_id != IPPROTO_TCP
		    && inner_ip4->next_proto_id != IPPROTO_UDP)
			return false;
		inner_l4 = (char *)inner_ip4 + rte_ipv4_hdr_len(inner_ip4);
		if (inner_ip4->next_proto_id == IPPROTO_UDP) {
			inner_udp = inner_l4;
			if (!inner_udp->dgram_cksum)
				return false;
		}
		inner_phdr_cksum = rte_ipv4_phdr_cksum(inner_ip4, 0);
	} else {
		inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		if (inner_ip6->proto != IPPROTO_TCP && inner_ip6->proto != IPPROTO_UDP)
			return false;
		inner_l4 = inner_ip6 + 1;
		if (inner_ip6->proto == IPPROTO_UDP) {
			inner_udp = inner_l4;
			if (!inner_udp->dgram_cksum)
				return false;
		}
		inner_phdr_cksum = rte_ipv6_phdr_cksum(inner_ip6, 0);
	}

	udp->dgram_cksum = 0;
	sum = __rte_raw_cksum(udp, (char *)inner_l4 - (char *)udp, 0);
	sum += outer_phdr_cksum;
	sum += (~inner_phdr_cksum) & 0xffff;
	sum += 0xffff;
	udp->dgram_cksum = ~__rte_raw_cksum_reduce(sum);
	if (!udp->dgram_cksum)
		udp->dgram_cksum = RTE_BE16(0xffff);

	return true;
}

static inline void gr_cksum_vxlan_tso_resolve(
	struct rte_mbuf *m,
	struct rte_udp_hdr *udp,
	uint16_t outer_phdr_cksum,
	uint64_t outer_ol_flags,
	uint16_t outer_l2_len,
	uint16_t outer_l3_len
) {
	struct rte_ipv4_hdr *inner_ip4;
	struct rte_ether_hdr *inner_eth;
	struct rte_tcp_hdr *tcp;
	uint16_t inner_ip_hdr_len;
	uint16_t inner_l2_len;
	uint16_t tcp_hdr_len;
	uint16_t payload_len;
	uint64_t ol_flags;

	if (gr_cksum_l4_partial(m))
		vxlan_const_udp_cksum(udp, outer_phdr_cksum);

	inner_eth = (struct rte_ether_hdr *)((struct rte_vxlan_hdr *)(udp + 1) + 1);
	if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
		inner_ip4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(inner_eth + 1) + 1);
		inner_l2_len = sizeof(*inner_eth) + sizeof(struct rte_vlan_hdr);
	} else {
		inner_ip4 = (struct rte_ipv4_hdr *)(inner_eth + 1);
		inner_l2_len = sizeof(*inner_eth);
	}

	ol_flags = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TUNNEL_VXLAN | RTE_MBUF_F_TX_TCP_CKSUM
		| outer_ol_flags;

	if (IS_IPV4(inner_ip4->version_ihl)) {
		inner_ip_hdr_len = rte_ipv4_hdr_len(inner_ip4);
		tcp = (struct rte_tcp_hdr *)((char *)inner_ip4 + inner_ip_hdr_len);
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		payload_len = rte_be_to_cpu_16(inner_ip4->total_length) - inner_ip_hdr_len
			- tcp_hdr_len;

		if (gr_cksum_l4_partial(m))
			udp->dgram_cksum = gr_cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);

		tcp->cksum = rte_ipv4_phdr_cksum(inner_ip4, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	} else {
		struct rte_ipv6_hdr *inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;

		inner_ip_hdr_len = sizeof(*inner_ip6);
		tcp = (struct rte_tcp_hdr *)(inner_ip6 + 1);
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		payload_len = rte_be_to_cpu_16(inner_ip6->payload_len) - tcp_hdr_len;

		if (gr_cksum_l4_partial(m)) {
			udp->dgram_cksum = gr_cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);
			udp->dgram_cksum = gr_cksum_update16(
				udp->dgram_cksum,
				rte_cpu_to_be_16(payload_len),
				rte_cpu_to_be_16(m->tso_segsz)
			);
		}

		tcp->cksum = rte_ipv6_phdr_cksum(inner_ip6, RTE_MBUF_F_TX_TCP_SEG);
		ol_flags |= RTE_MBUF_F_TX_IPV6;
	}

	m->outer_l2_len = outer_l2_len;
	m->outer_l3_len = outer_l3_len;
	m->l2_len = sizeof(struct rte_udp_hdr) + sizeof(struct rte_vxlan_hdr) + inner_l2_len;
	m->l3_len = inner_ip_hdr_len;
	m->l4_len = tcp_hdr_len;
	m->ol_flags |= ol_flags;
}

static inline void gr_cksum_resolve(struct rte_mbuf *m, uint64_t tx_offloads) {
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip4;

	if (!m->tso_segsz && !gr_cksum_l4_partial(m))
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

			if (m->tso_segsz && gr_cksum_inner_l4_partial(m)
			    && (tx_offloads & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO)) {
				gr_cksum_vxlan_tso_resolve(
					m,
					udp,
					rte_ipv4_phdr_cksum(ip4, 0),
					RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IP_CKSUM,
					(char *)ip4 - (char *)eth,
					(char *)udp - (char *)ip4
				);
				gr_cksum_reset(m);
				gr_cksum_ip_set_good(m);
				gr_cksum_l4_set_good(m);
				return;
			}
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
				if (m->tso_segsz && (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO)) {
					m->l4_len = (tcp->data_off >> 4) * 4;
					m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG
						| RTE_MBUF_F_TX_IP_CKSUM;
				}
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

			if (m->tso_segsz && gr_cksum_inner_l4_partial(m)
			    && (tx_offloads & RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO)) {
				gr_cksum_vxlan_tso_resolve(
					m,
					udp,
					rte_ipv6_phdr_cksum(ip6, 0),
					RTE_MBUF_F_TX_OUTER_IPV6,
					(char *)ip6 - (char *)eth,
					sizeof(*ip6)
				);
				gr_cksum_reset(m);
				gr_cksum_l4_set_good(m);
				return;
			}
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
				if (m->tso_segsz && (tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO)) {
					m->l4_len = (tcp->data_off >> 4) * 4;
					m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
				}
				tcp->cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
			} else {
				tcp->cksum = 0;
				tcp->cksum = rte_ipv6_udptcp_cksum(ip6, tcp);
			}
		}
	}

	gr_cksum_l4_set_good(m);
}
