// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

enum {
	IP_OUTPUT = 0,
	CONTROL,
	INVAL,
	ERROR,
	IGNORE,
	EDGE_COUNT,
};

static uint16_t ndp_ns_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop *local, *remote;
	struct icmp6_neigh_solicit *ns;
	struct icmp6_neigh_advert *na;
	struct ip6_local_mbuf_data *d;
	struct rte_ipv6_addr src, dst;
	struct rte_ether_addr lladdr;
	struct icmp6_opt_lladdr *ll;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	struct icmp6_opt *opt;
	struct rte_mbuf *mbuf;
	uint16_t payload_len;
	struct icmp6 *icmp6;
	bool lladdr_found;
	rte_edge_t next;
	bool solicited;

#define ASSERT_NDP(condition)                                                                      \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			next = INVAL;                                                              \
			goto next;                                                                 \
		}                                                                                  \
	} while (0)

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		ns = PAYLOAD(icmp6);
		iface = d->iface;
		src = d->src;
		dst = d->dst;

		// Validation of Neighbor Solicitations
		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1
		//
		// - The IP Hop Limit field has a value of 255, i.e., the packet
		//   could not possibly have been forwarded by a router.
		ASSERT_NDP(d->hop_limit == 255);
		// - ICMP Checksum is valid. (already checked in icmp6_input)
		//
		// - ICMP Code is 0.
		ASSERT_NDP(icmp6->code == 0);
		// - ICMP length (derived from the IP length) is 24 or more octets.
		ASSERT_NDP(d->len >= 0);
		// - Target Address is not a multicast address.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&ns->target));

		local = ip6_nexthop_lookup(iface->vrf_id, iface->id, &ns->target);
		if (local == NULL || !(local->flags & GR_NH_F_LOCAL)) {
			next = IGNORE;
			if (gr_mbuf_is_traced(mbuf))
				gr_mbuf_trace_add(mbuf, node, 0);
			goto next;
		}

		lladdr_found = icmp6_get_opt(
			mbuf, sizeof(*icmp6) + sizeof(*ns), ICMP6_OPT_SRC_LLADDR, &lladdr
		);

		if (rte_ipv6_addr_is_unspec(&src)) {
			// - If the IP source address is the unspecified address, the IP
			//   destination address is a solicited-node multicast address.
			ASSERT_NDP(rte_ipv6_addr_is_mcast(&dst));
			// - If the IP source address is the unspecified address, there is
			//   no source link-layer address option in the message.
			ASSERT_NDP(!lladdr_found);
			// If the source of the solicitation is the unspecified address, the
			// node MUST set the Solicited flag to zero and multicast the
			// advertisement to the all-nodes address.
			src = (struct rte_ipv6_addr)RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL;
			solicited = false;
			remote = NULL;
		} else {
			// Otherwise, the node MUST set the Solicited flag to one and unicast the
			// advertisement to the Source Address of the solicitation.
			solicited = true;
			remote = ip6_nexthop_lookup(iface->vrf_id, iface->id, &src);

			if (lladdr_found) {
				// Copy the NS probe and send it to control plane for processing.
				struct rte_mbuf *copy = rte_pktmbuf_copy(
					mbuf, mbuf->pool, 0, UINT32_MAX
				);
				if (copy == NULL) {
					next = ERROR;
					if (gr_mbuf_is_traced(mbuf))
						gr_mbuf_trace_add(mbuf, node, 0);
					goto next;
				}
				if (gr_mbuf_is_traced(mbuf))
					gr_mbuf_trace_add(copy, node, 0);

				// HACK: replace the target IP with the *SOURCE* address of the NS
				// sender. This removes the need to copy the whole IPv6 header for
				// ndp_probe_input_cb.
				ns = PAYLOAD(rte_pktmbuf_mtod(copy, struct icmp6 *));
				ns->target = src;

				struct control_output_mbuf_data *d;
				d = control_output_mbuf_data(copy);
				d->iface = iface;
				d->callback = ndp_probe_input_cb;
				rte_node_enqueue_x1(graph, node, CONTROL, copy);
			}
		}

		// Reuse the mbuf to forge a neighbour advertisement reply.
		// XXX,TODO: avoid issues with encap, remember previous data offset?
		rte_pktmbuf_reset(mbuf);
		icmp6 = (struct icmp6 *)rte_pktmbuf_append(mbuf, sizeof(*icmp6));
		icmp6->type = ICMP6_TYPE_NEIGH_ADVERT;
		icmp6->code = 0;
		na = (struct icmp6_neigh_advert *)rte_pktmbuf_append(mbuf, sizeof(*na));
		na->override = 1;
		na->router = 1;
		na->solicited = solicited;
		na->target = local->ipv6;

		opt = (struct icmp6_opt *)rte_pktmbuf_append(mbuf, sizeof(*opt));
		opt->type = ICMP6_OPT_TARGET_LLADDR;
		opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*ll));
		ll = (struct icmp6_opt_lladdr *)rte_pktmbuf_append(mbuf, sizeof(*ll));
		ll->mac = local->lladdr;

		// ip6_output needs a nexthop to know the output interface. If we do not
		// currently have a remote nexthop, set it to the interface that has the
		// solicited address. If the source IP address is not unspecified AND
		// a link-layer address option is present, the nexthop will be replaced
		// with the remote one.
		ip6_output_mbuf_data(mbuf)->nh = remote ?: local;

		// Fill IPv6 layer
		payload_len = rte_pktmbuf_pkt_len(mbuf);
		ip = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		ip6_set_fields(ip, payload_len, IPPROTO_ICMPV6, &na->target, &src);
		// Compute ICMP6 checksum with pseudo header
		icmp6->cksum = 0;
		icmp6->cksum = rte_ipv6_udptcp_cksum(ip, icmp6);

		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(payload_len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}
		next = IP_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_ns_input",

	.process = ndp_ns_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip6_output",
		[CONTROL] = "control_output",
		[INVAL] = "ndp_ns_input_inval",
		[ERROR] = "ndp_ns_input_error",
		[IGNORE] = "ndp_ns_input_ignore",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_ns_input_inval);
GR_DROP_REGISTER(ndp_ns_input_error);
GR_DROP_REGISTER(ndp_ns_input_ignore);
