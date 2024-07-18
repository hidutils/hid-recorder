// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Benjamin Tissoires
 */
#include "hidrecord.h"

#define BPF_F_BEFORE (1U << 3)

SEC("struct_ops/hid_device_event")
int BPF_PROG(hid_record_event, struct hid_bpf_ctx *hctx)
{
	return process_event(hctx);
}

SEC(".struct_ops.link")
struct hid_bpf_ops hid_record = {
	.hid_device_event = (void *)hid_record_event,
	.flags = BPF_F_BEFORE,
};
