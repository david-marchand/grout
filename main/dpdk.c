// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "dpdk.h"

#include <br_api.h>
#include <br_log.h>
#include <br_stb_ds.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_version.h>

#include <sched.h>

int br_rte_log_type;

int dpdk_init(struct boring_router *br) {
	char **eal_args = NULL;
	int ret = -1;

	arrpush(eal_args, "");
	arrpush(eal_args, "-l");
	arrpush(eal_args, "0");
	arrpush(eal_args, "-a");
	arrpush(eal_args, "0000:00:00.0");

	if (br->test_mode) {
		arrpush(eal_args, "--no-shconf");
		arrpush(eal_args, "--no-huge");
		arrpush(eal_args, "-m");
		arrpush(eal_args, "1024");
	} else {
		arrpush(eal_args, "--in-memory");
	}
	if (br->log_level >= RTE_LOG_DEBUG) {
		arrpush(eal_args, "--log-level=*:debug");
	} else if (br->log_level >= RTE_LOG_INFO) {
		arrpush(eal_args, "--log-level=*:info");
	} else {
		arrpush(eal_args, "--log-level=*:notice");
	}

	LOG(INFO, "DPDK version: %s", rte_version());

	br_rte_log_type = rte_log_register_type_and_pick_level("br", RTE_LOG_INFO);
	if (br_rte_log_type < 0)
		goto end;

	char *buf = arrjoin(eal_args, " ");
	LOG(INFO, "EAL arguments:%s", buf);
	free(buf);

	if (rte_eal_init(arrlen(eal_args), eal_args) < 0)
		goto end;

	ret = 0;
end:
	arrfree(eal_args);
	return ret;
}

void dpdk_fini(void) {
	rte_eal_cleanup();
}