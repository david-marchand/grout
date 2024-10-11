// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IPIP_PRIV_H
#define _IPIP_PRIV_H

#include <gr_iface.h>
#include <gr_net_types.h>

#include <stdint.h>

struct __rte_aligned(alignof(void *)) iface_info_ipip {
	ip4_addr_t local;
	ip4_addr_t remote;
};

struct iface *ipip_get_iface(ip4_addr_t local, ip4_addr_t remote, uint16_t vrf_id);

struct trace_ipip_data {
	uint16_t iface_id;
};

int trace_ipip_format(char *buf, size_t len, const void *data, size_t data_len);

#endif
