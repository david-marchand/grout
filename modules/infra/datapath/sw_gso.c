// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#include "graph.h"
#include "mbuf.h"
#include "rxtx.h"
#include "sw_gso.h"

#include <rte_graph.h>

enum {
	PORT_TX = 0,
	SW_GSO_ERROR,
	NB_EDGES,
};

static inline uint16_t sw_gso_l2_len(struct rte_mbuf *m) {
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		return sizeof(*eth) + sizeof(struct rte_vlan_hdr);
	return sizeof(*eth);
}

static inline void sw_gso_update_segment(
	struct rte_mbuf *seg,
	uint16_t l2_len,
	uint16_t ip_hdr_len,
	uint16_t tcp_hdr_len,
	uint16_t payload_len,
	uint16_t id_off,
	uint32_t seq_off,
	bool last
) {
	struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(seg, struct rte_ipv4_hdr *, l2_len);

	if (IS_IPV4(ip4->version_ihl)) {
		ip4->total_length = rte_cpu_to_be_16(ip_hdr_len + tcp_hdr_len + payload_len);
		ip4->packet_id = rte_cpu_to_be_16(rte_be_to_cpu_16(ip4->packet_id) + id_off);
		ip4->hdr_checksum = 0;
		ip4->hdr_checksum = rte_ipv4_cksum(ip4);
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;
		ip6->payload_len = rte_cpu_to_be_16(tcp_hdr_len + payload_len);
	}

	struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
		seg, struct rte_tcp_hdr *, l2_len + ip_hdr_len
	);
	tcp->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->sent_seq) + seq_off);
	if (!last)
		tcp->tcp_flags &= ~(RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG);
	tcp->cksum = 0;

	seg->tso_segsz = 0;
	gr_cksum_reset(seg);
	gr_cksum_l4_set_partial(seg);
	if (IS_IPV4(ip4->version_ihl))
		gr_cksum_ip_set_good(seg);
}

static inline uint16_t
sw_gso_segment(struct rte_mbuf *m, uint16_t l2_len, struct rte_mbuf **segs, uint16_t max_segs) {
	uint16_t seg_payload_len, payload_off;
	uint16_t inner_ip_hdr_len;
	uint16_t tunnel_hdr_len;
	bool outer_l4_partial;
	uint16_t tcp_hdr_len;
	uint16_t payload_len;
	uint16_t ip_hdr_len;
	struct rte_mbuf *seg;
	uint16_t tso_segsz;
	uint16_t hdr_len;
	uint16_t n_segs;
	bool tunnel = false;
	uint16_t i;
	void *dst;

	tso_segsz = m->tso_segsz;
	if (!tso_segsz)
		return 0;

	struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, l2_len);

	if (IS_IPV4(ip4->version_ihl)) {
		ip_hdr_len = rte_ipv4_hdr_len(ip4);
		if (ip4->next_proto_id == IPPROTO_UDP) {
			tunnel = gr_cksum_inner_l4_partial(m);
			if (!tunnel)
				return 0;
		} else if (ip4->next_proto_id != IPPROTO_TCP) {
			return 0;
		}
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)ip4;
		ip_hdr_len = sizeof(*ip6);
		if (ip6->proto == IPPROTO_UDP) {
			tunnel = gr_cksum_inner_l4_partial(m);
			if (!tunnel)
				return 0;
		} else if (ip6->proto != IPPROTO_TCP) {
			return 0;
		}
	}

	struct rte_tcp_hdr *tcp;

	if (tunnel) {
		struct rte_ether_hdr *inner_eth;
		struct rte_ipv4_hdr *inner_ip4;
		uint16_t inner_l2_len;

		inner_eth = rte_pktmbuf_mtod_offset(
			m,
			struct rte_ether_hdr *,
			l2_len + ip_hdr_len + sizeof(struct rte_udp_hdr)
				+ sizeof(struct rte_vxlan_hdr)
		);
		if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
			inner_l2_len = sizeof(*inner_eth) + sizeof(struct rte_vlan_hdr);
		else
			inner_l2_len = sizeof(*inner_eth);

		tunnel_hdr_len = l2_len + ip_hdr_len + sizeof(struct rte_udp_hdr)
			+ sizeof(struct rte_vxlan_hdr) + inner_l2_len;
		inner_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, tunnel_hdr_len);

		if (IS_IPV4(inner_ip4->version_ihl)) {
			if (inner_ip4->next_proto_id != IPPROTO_TCP)
				return 0;
			inner_ip_hdr_len = rte_ipv4_hdr_len(inner_ip4);
		} else {
			struct rte_ipv6_hdr *inner_ip6 = (struct rte_ipv6_hdr *)inner_ip4;
			if (inner_ip6->proto != IPPROTO_TCP)
				return 0;
			inner_ip_hdr_len = sizeof(*inner_ip6);
		}

		tcp = rte_pktmbuf_mtod_offset(
			m, struct rte_tcp_hdr *, tunnel_hdr_len + inner_ip_hdr_len
		);
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		hdr_len = tunnel_hdr_len + inner_ip_hdr_len + tcp_hdr_len;
		outer_l4_partial = gr_cksum_l4_partial(m);
	} else {
		tunnel_hdr_len = 0;
		inner_ip_hdr_len = 0;
		outer_l4_partial = false;

		tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, l2_len + ip_hdr_len);
		tcp_hdr_len = (tcp->data_off >> 4) * 4;
		hdr_len = l2_len + ip_hdr_len + tcp_hdr_len;
	}

	payload_len = rte_pktmbuf_pkt_len(m) - hdr_len;

	n_segs = (payload_len + tso_segsz - 1) / tso_segsz;
	if (n_segs == 0 || n_segs > max_segs)
		return 0;

	for (i = 1; i < n_segs; i++) {
		payload_off = i * tso_segsz;
		seg_payload_len = RTE_MIN(tso_segsz, payload_len - payload_off);

		seg = gr_mbuf_copy(m, hdr_len);
		if (seg == NULL)
			goto error;

		dst = rte_pktmbuf_append(seg, seg_payload_len);
		if (dst == NULL) {
			rte_pktmbuf_free(seg);
			goto error;
		}

		memcpy(dst,
		       rte_pktmbuf_mtod_offset(m, const void *, hdr_len + payload_off),
		       seg_payload_len);

		if (tunnel)
			sw_gso_update_vxlan_segment(
				seg,
				l2_len,
				ip_hdr_len,
				tunnel_hdr_len,
				inner_ip_hdr_len,
				tcp_hdr_len,
				seg_payload_len,
				i,
				payload_off,
				i == n_segs - 1,
				outer_l4_partial
			);
		else
			sw_gso_update_segment(
				seg,
				l2_len,
				ip_hdr_len,
				tcp_hdr_len,
				seg_payload_len,
				i,
				payload_off,
				i == n_segs - 1
			);

		segs[i] = seg;
	}

	seg_payload_len = RTE_MIN(tso_segsz, payload_len);
	rte_pktmbuf_trim(m, payload_len - seg_payload_len);
	if (tunnel)
		sw_gso_update_vxlan_segment(
			m,
			l2_len,
			ip_hdr_len,
			tunnel_hdr_len,
			inner_ip_hdr_len,
			tcp_hdr_len,
			seg_payload_len,
			0,
			0,
			n_segs == 1,
			outer_l4_partial
		);
	else
		sw_gso_update_segment(
			m, l2_len, ip_hdr_len, tcp_hdr_len, seg_payload_len, 0, 0, n_segs == 1
		);

	segs[0] = m;
	return n_segs;

error:
	for (uint16_t j = 1; j < i; j++)
		rte_pktmbuf_free(segs[j]);
	return 0;
}

static inline uint16_t sw_gso_do(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	bool l2_hdr
) {
	uint16_t n_segs, max_out, idx;
	void **next;

	max_out = 0;
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *m = objs[i];
		if (m->tso_segsz)
			max_out += (rte_pktmbuf_pkt_len(m) + m->tso_segsz - 1) / m->tso_segsz;
		else
			max_out++;
	}
	next = rte_node_next_stream_get(graph, node, 0, max_out);
	idx = 0;
	for (uint16_t i = 0; i < nb_objs; i++) {
		struct rte_mbuf *m = objs[i];
		if (!m->tso_segsz) {
			next[idx++] = m;
			continue;
		}
		n_segs = sw_gso_segment(
			m,
			l2_hdr ? sw_gso_l2_len(m) : 0,
			(struct rte_mbuf **)&next[idx],
			max_out - idx
		);
		if (n_segs == 0) {
			rte_node_enqueue_x1(graph, node, 1, m);
			continue;
		}
		idx += n_segs;
	}
	rte_node_next_stream_put(graph, node, 0, idx);
	return nb_objs;
}

static uint16_t
sw_gso_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	return sw_gso_do(graph, node, objs, nb_objs, true);
}

uint16_t sw_gso_tunnel_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	return sw_gso_do(graph, node, objs, nb_objs, false);
}

static struct rte_node_register sw_gso_node = {
	.name = SW_GSO_NODE_BASE,
	.process = sw_gso_process,
	.nb_edges = NB_EDGES,
	.next_nodes = {
		[PORT_TX] = "port_tx",
		[SW_GSO_ERROR] = "sw_gso_error",
	},
};

static struct gr_node_info sw_gso_info = {
	.node = &sw_gso_node,
	.type = GR_NODE_T_L1,
};

GR_NODE_REGISTER(sw_gso_info);

GR_DROP_REGISTER(sw_gso_error);
