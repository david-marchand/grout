// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include "cksum.h"

#include <rte_graph.h>

#define SW_GSO_NODE_BASE "sw_gso"
#define SW_GSO_NODE_FMT SW_GSO_NODE_BASE "-p%uq%u"

static inline void sw_gso_update_vxlan_segment(
	struct rte_mbuf *seg,
	uint16_t l2_len,
	uint16_t ip_hdr_len,
	uint16_t tunnel_hdr_len,
	uint16_t inner_ip_hdr_len,
	uint16_t tcp_hdr_len,
	uint16_t payload_len,
	uint16_t id_off,
	uint32_t seq_off,
	bool last,
	bool outer_l4_partial
) {
	uint16_t inner_l2_len = tunnel_hdr_len - l2_len - ip_hdr_len - sizeof(struct rte_udp_hdr)
		- sizeof(struct rte_vxlan_hdr);
	uint16_t inner_total = inner_ip_hdr_len + tcp_hdr_len + payload_len;
	uint16_t udp_payload_len = sizeof(struct rte_vxlan_hdr) + inner_l2_len + inner_total;
	uint16_t outer_total = ip_hdr_len + sizeof(struct rte_udp_hdr) + udp_payload_len;
	uint16_t outer_phdr_cksum;

	struct rte_ipv4_hdr *inner_ip4 = rte_pktmbuf_mtod_offset(
		seg, struct rte_ipv4_hdr *, tunnel_hdr_len
	);
	struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
		seg, struct rte_tcp_hdr *, tunnel_hdr_len + inner_ip_hdr_len
	);

	tcp->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->sent_seq) + seq_off);
	if (!last)
		tcp->tcp_flags &= ~(RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG);
	tcp->cksum = 0;

	if (IS_IPV4(inner_ip4->version_ihl)) {
		inner_ip4->total_length = rte_cpu_to_be_16(inner_total);
		inner_ip4->packet_id = rte_cpu_to_be_16(
			rte_be_to_cpu_16(inner_ip4->packet_id) + id_off
		);
		inner_ip4->hdr_checksum = 0;
		inner_ip4->hdr_checksum = rte_ipv4_cksum(inner_ip4);
		tcp->cksum = rte_ipv4_udptcp_cksum(inner_ip4, tcp);
	} else {
		struct rte_ipv6_hdr *inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		inner_ip6->payload_len = rte_cpu_to_be_16(tcp_hdr_len + payload_len);
		tcp->cksum = rte_ipv6_udptcp_cksum(inner_ip6, tcp);
	}

	struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
		seg, struct rte_udp_hdr *, l2_len + ip_hdr_len
	);
	udp->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + udp_payload_len);
	udp->dgram_cksum = 0;

	struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(seg, struct rte_ipv4_hdr *, l2_len);
	if (IS_IPV4(ip4->version_ihl)) {
		ip4->total_length = rte_cpu_to_be_16(outer_total);
		ip4->hdr_checksum = 0;
		ip4->hdr_checksum = rte_ipv4_cksum(ip4);
		outer_phdr_cksum = rte_ipv4_phdr_cksum(ip4, 0);
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;
		ip6->payload_len = rte_cpu_to_be_16(outer_total - sizeof(*ip6));
		outer_phdr_cksum = rte_ipv6_phdr_cksum(ip6, 0);
	}

	if (outer_l4_partial)
		vxlan_const_udp_cksum(udp, outer_phdr_cksum);

	seg->tso_segsz = 0;
	gr_cksum_reset(seg);
	if (IS_IPV4(ip4->version_ihl))
		gr_cksum_ip_set_good(seg);
	gr_cksum_l4_set_good(seg);
}

uint16_t sw_gso_tunnel_process(struct rte_graph *, struct rte_node *, void **, uint16_t);
