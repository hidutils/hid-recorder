// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Benjamin Tissoires
 */
#include "hidrecord.h"

extern int hid_bpf_attach_prog(unsigned int hid_id, int prog_fd, u32 flags) __ksym;

#define HID_BPF_F_BEFORE (1U)

struct attach_prog_args {
	int prog_fd;
	unsigned int hid;
	int retval;
};

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_record_event, struct hid_bpf_ctx *hctx)
{
	return process_event(hctx);
}

SEC("syscall")
int attach_prog(struct attach_prog_args *ctx)
{
	ctx->retval = hid_bpf_attach_prog(ctx->hid, ctx->prog_fd, HID_BPF_F_BEFORE);
	return 0;
}
