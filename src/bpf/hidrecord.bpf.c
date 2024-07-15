// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Benjamin Tissoires
 */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct hid_recorder_event {
	__u8 length;
	__u8 data[64];
};

extern __u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx,
			      unsigned int offset,
			      const size_t __sz) __ksym;

#define BPF_F_BEFORE (1U << 3)

SEC("struct_ops/hid_device_event")
int BPF_PROG(hid_record_event, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 64 /* size */);
	struct hid_recorder_event *event;

	if (!data)
		return 0; /* EPERM check */

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->length = hctx->size;
	__builtin_memcpy(event->data, data, sizeof(event->data));

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC(".struct_ops.link")
struct hid_bpf_ops hid_record = {
	.hid_device_event = (void *)hid_record_event,
	.flags = BPF_F_BEFORE,
};
