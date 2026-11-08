// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include "cksum.h"

#include <rte_graph.h>

#define SW_GSO_NODE_BASE "sw_gso"
#define SW_GSO_NODE_FMT SW_GSO_NODE_BASE "-p%uq%u"

uint16_t sw_gso_tunnel_process(struct rte_graph *, struct rte_node *, void **, uint16_t);
uint16_t sw_gso_vxlan_process(struct rte_graph *, struct rte_node *, void **, uint16_t);
