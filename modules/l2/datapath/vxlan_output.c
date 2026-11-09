// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "cksum.h"
#include "graph.h"
#include "ip4.h"
#include "ip6.h"
#include "l2.h"
#include "l2_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "rxtx.h"
#include "sw_gso.h"

#include <rte_byteorder.h>
#include <rte_ip6.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

enum {
	IP_OUTPUT = 0,
	IP6_OUTPUT,
	NO_ROUTE,
	NO_HEADROOM,
	NO_AF,
	EDGE_COUNT,
};

#define EPHEMERAL_PORT_START 49152
#define EPHEMERAL_PORT_MASK (UINT16_MAX - EPHEMERAL_PORT_START)

static inline rte_be16_t vxlan_src_port(uint32_t hash) {
	// RFC 7348 Section 5, recommends using source port hashing to enable
	// ECMP load balancing in the underlay network.
	return rte_cpu_to_be_16(EPHEMERAL_PORT_START + (hash & EPHEMERAL_PORT_MASK));
}

static struct rte_mbuf *vxlan_tso_partial_seg(struct rte_mbuf *m, int af, uint16_t vxlan_flags) {
	struct rte_ether_hdr *inner_eth;
	struct rte_ipv4_hdr *inner_ip4;
	uint16_t inner_ip_hdr_len;
	uint16_t tunnel_hdr_len;
	struct rte_tcp_hdr *tcp;
	uint16_t remainder_len;
	uint16_t outer_hdr_len;
	uint16_t inner_l2_len;
	uint16_t tcp_hdr_len;
	uint32_t payload_len;
	struct rte_mbuf *rem;
	uint16_t ip_hdr_len;
	uint16_t tso_segsz;
	uint16_t hdr_len;
	uint16_t n_segs;
	void *dst;

	if (af == GR_AF_IP4)
		outer_hdr_len = sizeof(struct vxlan_template_ipv4);
	else
		outer_hdr_len = sizeof(struct vxlan_template_ipv6);

	ip_hdr_len = outer_hdr_len - sizeof(struct rte_udp_hdr) - sizeof(struct rte_vxlan_hdr);
	tso_segsz = m->tso_segsz;

	inner_eth = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, outer_hdr_len);
	inner_l2_len = sizeof(*inner_eth);
	if (inner_eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN))
		inner_l2_len += sizeof(struct rte_vlan_hdr);

	tunnel_hdr_len = outer_hdr_len + inner_l2_len;
	inner_ip4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, tunnel_hdr_len);

	if (IS_IPV4(inner_ip4->version_ihl)) {
		if (inner_ip4->next_proto_id != IPPROTO_TCP)
			return NULL;
		inner_ip_hdr_len = rte_ipv4_hdr_len(inner_ip4);
	} else {
		struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)inner_ip4;
		if (ip6->proto != IPPROTO_TCP)
			return NULL;
		inner_ip_hdr_len = sizeof(*ip6);
	}

	tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, tunnel_hdr_len + inner_ip_hdr_len);
	tcp_hdr_len = (tcp->data_off >> 4) * 4;
	hdr_len = tunnel_hdr_len + inner_ip_hdr_len + tcp_hdr_len;
	payload_len = rte_pktmbuf_pkt_len(m) - hdr_len;

	n_segs = payload_len / tso_segsz;
	remainder_len = payload_len - (uint32_t)n_segs * tso_segsz;

	if (remainder_len == 0 || n_segs == 0)
		return NULL;

	rem = gr_mbuf_copy(m, hdr_len);
	if (rem == NULL)
		return NULL;

	dst = rte_pktmbuf_append(rem, remainder_len);
	if (dst == NULL) {
		rte_pktmbuf_free(rem);
		return NULL;
	}
	memcpy(dst,
	       rte_pktmbuf_mtod_offset(m, const void *, hdr_len + (uint32_t)n_segs * tso_segsz),
	       remainder_len);

	bool outer_l4_partial = vxlan_flags & GR_VXLAN_F_UDP_CKSUM;

	sw_gso_update_vxlan_segment(
		rem,
		0,
		ip_hdr_len,
		tunnel_hdr_len,
		inner_ip_hdr_len,
		tcp_hdr_len,
		remainder_len,
		0,
		(uint32_t)n_segs * tso_segsz,
		true,
		outer_l4_partial
	);

	rte_pktmbuf_trim(m, remainder_len);

	if (n_segs == 1) {
		sw_gso_update_vxlan_segment(
			m,
			0,
			ip_hdr_len,
			tunnel_hdr_len,
			inner_ip_hdr_len,
			tcp_hdr_len,
			tso_segsz,
			0,
			0,
			false,
			outer_l4_partial
		);
	} else {
		tcp->tcp_flags &= ~(RTE_TCP_PSH_FLAG | RTE_TCP_FIN_FLAG);

		if (IS_IPV4(inner_ip4->version_ihl)) {
			inner_ip4->total_length = rte_cpu_to_be_16(
				inner_ip_hdr_len + tcp_hdr_len + (uint32_t)n_segs * tso_segsz
			);
			inner_ip4->hdr_checksum = 0;
			inner_ip4->hdr_checksum = rte_ipv4_cksum(inner_ip4);
		} else {
			struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)inner_ip4;
			ip6->payload_len = rte_cpu_to_be_16(
				tcp_hdr_len + (uint32_t)n_segs * tso_segsz
			);
		}

		if (af == GR_AF_IP4) {
			struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip4 + 1);
			uint16_t pkt_len = rte_pktmbuf_pkt_len(m);
			ip4->total_length = rte_cpu_to_be_16(pkt_len);
			ip4->hdr_checksum = 0;
			ip4->hdr_checksum = rte_ipv4_cksum(ip4);
			udp->dgram_len = rte_cpu_to_be_16(pkt_len - sizeof(*ip4));
		} else {
			struct rte_ipv6_hdr *ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip6 + 1);
			uint16_t pkt_len = rte_pktmbuf_pkt_len(m);
			ip6->payload_len = rte_cpu_to_be_16(pkt_len - sizeof(*ip6));
			udp->dgram_len = ip6->payload_len;
		}
	}

	return rem;
}

static uint16_t vxlan_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface_info_vxlan *vxlan;
	struct vxlan_template_ipv4 *vh4;
	struct vxlan_template_ipv6 *vh6;
	struct iface_mbuf_data *d;
	const struct nexthop *nh;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint16_t len;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		vxlan = iface_info_vxlan(d->iface);

		// EVPN advertises IPv4 VTEPs as IPv4-mapped IPv6 addresses
		// (::ffff:a.b.c.d) in the IPv6 address family. The tunnel
		// underlay is IPv4: unmap the address so that the IPv4
		// encapsulation template is used.
		if (d->vtep.af == GR_AF_IP6 && rte_ipv6_addr_is_v4mapped(&d->vtep.ipv6)) {
			ip4_addr_t v4;

			memcpy(&v4, &d->vtep.ipv6.a[12], sizeof(v4));
			d->vtep.af = GR_AF_IP4;
			d->vtep.ipv4 = v4;
		}

		if (gr_mbuf_is_traced(m)) {
			struct trace_vxlan_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->vni = rte_cpu_to_be_32(vxlan->vni);
			t->vtep = d->vtep;
		}

		if (!m->tso_segsz)
			gr_cksum_resolve(m, 0);

		len = rte_pktmbuf_pkt_len(m);

		switch (d->vtep.af) {
		case GR_AF_IP4:
			nh = fib4_lookup(vxlan->encap_vrf_id, d->vtep.ipv4, m->hash.rss);
			if (nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}

			vh4 = gr_mbuf_prepend(m, vh4);
			if (unlikely(vh4 == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			*vh4 = vxlan->template.ipv4;
			vh4->udp.src_port = vxlan_src_port(m->hash.rss);
			vh4->udp.dgram_len = rte_cpu_to_be_16(
				len + sizeof(vh4->udp) + sizeof(vh4->vxlan)
			);
			vh4->ip.dst_addr = d->vtep.ipv4;
			vh4->ip.total_length = rte_cpu_to_be_16(len + sizeof(*vh4));
			vh4->ip.hdr_checksum = rte_ipv4_cksum(&vh4->ip);
			gr_cksum_reset(m);
			gr_cksum_ip_set_good(m);
			if (m->tso_segsz) {
				gr_cksum_inner_l4_set_partial(m);
				if (vxlan->flags & GR_VXLAN_F_UDP_CKSUM)
					gr_cksum_l4_set_partial(m);
			} else if (vxlan->flags & GR_VXLAN_F_UDP_CKSUM) {
				if (vxlan_const_udp_cksum(
					    &vh4->udp, rte_ipv4_phdr_cksum(&vh4->ip, 0)
				    ))
					gr_cksum_l4_set_good(m);
				else
					gr_cksum_l4_set_partial(m);
			}

			edge = IP_OUTPUT;
			break;
		case GR_AF_IP6:
			nh = fib6_lookup(
				vxlan->encap_vrf_id, d->iface->id, &d->vtep.ipv6, m->hash.rss
			);
			if (nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}

			vh6 = gr_mbuf_prepend(m, vh6);
			if (unlikely(vh6 == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			*vh6 = vxlan->template.ipv6;
			vh6->udp.src_port = vxlan_src_port(m->hash.rss);
			vh6->udp.dgram_len = rte_cpu_to_be_16(
				len + sizeof(vh6->udp) + sizeof(vh6->vxlan)
			);
			vh6->ip.dst_addr = d->vtep.ipv6;
			vh6->ip.payload_len = vh6->udp.dgram_len;
			gr_cksum_reset(m);
			if (m->tso_segsz) {
				gr_cksum_inner_l4_set_partial(m);
				if (vxlan->flags & GR_VXLAN_F_UDP_CKSUM)
					gr_cksum_l4_set_partial(m);
			} else if (vxlan->flags & GR_VXLAN_F_UDP_CKSUM) {
				if (vxlan_const_udp_cksum(
					    &vh6->udp, rte_ipv6_phdr_cksum(&vh6->ip, 0)
				    ))
					gr_cksum_l4_set_good(m);
				else
					gr_cksum_l4_set_partial(m);
			}

			edge = IP6_OUTPUT;
			break;
		default:
			edge = NO_AF;
			goto next;
		}
		l3_mbuf_data(m)->nh = nh;
		// Align TSO payload on tso_segsz for HW tunnel TSO.
		if (m->tso_segsz) {
			struct rte_mbuf *rem = vxlan_tso_partial_seg(m, d->vtep.af, vxlan->flags);
			if (rem) {
				l3_mbuf_data(rem)->nh = nh;
				rte_node_enqueue_x1(graph, node, edge, m);
				rte_node_enqueue_x1(graph, node, edge, rem);
				continue;
			}
		}
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void vxlan_output_register(void) {
	iface_output_type_register(GR_IFACE_TYPE_VXLAN, "vxlan_output");
}

static struct rte_node_register vxlan_output_node = {
	.name = "vxlan_output",

	.process = vxlan_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[IP6_OUTPUT] = "ip6_output",
		[NO_ROUTE] = "vxlan_output_no_route",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_AF] = "vxlan_output_no_af",
	},
};

static struct gr_node_info vxlan_output_info = {
	.node = &vxlan_output_node,
	.type = GR_NODE_T_L3,
	.register_callback = vxlan_output_register,
	.trace_format = trace_vxlan_format,
};

GR_NODE_REGISTER(vxlan_output_info);

GR_DROP_REGISTER(vxlan_output_no_route);
GR_DROP_REGISTER(vxlan_output_no_af);
