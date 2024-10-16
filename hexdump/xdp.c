/*
* SPDX-FileCopyrightText: (c) 2024 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

extern int bpf_luaxdp_run(char *key, size_t key__sz, struct xdp_md *xdp_ctx, void *arg, size_t arg__sz) __ksym;

static char runtime[] = "hexdump/hook";

struct bpf_luaxdp_arg {
	__u16 offset;
} __attribute__((packed));

SEC("xdp")
int filter(struct xdp_md *ctx)
{
	struct bpf_luaxdp_arg arg;

	arg.offset = bpf_htons((__u16)(sizeof(struct ethhdr)));

	int action = bpf_luaxdp_run(runtime, sizeof(runtime), ctx, &arg, sizeof(arg));
	return action < 0 ? XDP_PASS : action;
}

char _license[] SEC("license") = "Dual MIT/GPL";

