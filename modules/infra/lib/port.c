// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int br_infra_port_add(const struct br_client *c, const char *devargs, uint16_t *port_id) {
	struct br_infra_port_add_resp *resp = NULL;
	struct br_infra_port_add_req req;

	memset(&req, 0, sizeof(req));
	memccpy(req.devargs, devargs, 0, sizeof(req.devargs));

	if (send_recv(c, BR_INFRA_PORT_ADD, sizeof(req), &req, (void **)&resp) < 0)
		return -1;

	if (port_id != NULL)
		*port_id = resp->port_id;

	free(resp);

	return 0;
}

int br_infra_port_del(const struct br_client *c, uint16_t port_id) {
	struct br_infra_port_del_req req = {port_id};

	return send_recv(c, BR_INFRA_PORT_DEL, sizeof(req), &req, NULL);
}

int br_infra_port_get(const struct br_client *c, uint16_t port_id, struct br_infra_port *port) {
	struct br_infra_port_get_req req = {port_id};
	struct br_infra_port_get_resp *resp = NULL;

	if (port == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (send_recv(c, BR_INFRA_PORT_GET, sizeof(req), &req, (void **)&resp) < 0)
		return -1;

	memcpy(port, &resp->port, sizeof(*port));

	return 0;
}

int br_infra_port_list(const struct br_client *c, size_t *n_ports, struct br_infra_port **ports) {
	struct br_infra_port_list_resp *resp = NULL;

	if (ports == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (send_recv(c, BR_INFRA_PORT_LIST, 0, NULL, (void **)&resp) < 0)
		return -1;

	*n_ports = resp->n_ports;
	*ports = calloc(resp->n_ports, sizeof(struct br_infra_port));
	if (*ports == NULL) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(*ports, &resp->ports, resp->n_ports * sizeof(struct br_infra_port));
	free(resp);

	return 0;
}

int br_infra_port_set(const struct br_client *c, uint16_t port_id, uint16_t n_rxq) {
	struct br_infra_port_set_req req = {
		.port_id = port_id,
		.set_attrs = BR_INFRA_PORT_N_RXQ,
		.n_rxq = n_rxq,
	};

	return send_recv(c, BR_INFRA_PORT_SET, sizeof(req), &req, NULL);
}