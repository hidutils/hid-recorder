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

#define PACKET_SIZE 64
#define HID_MAX_BUFFER_SIZE	16384		/* 16kb, from include/linux/hid.h */
#define HID_MAX_PACKET (HID_MAX_BUFFER_SIZE / PACKET_SIZE)

struct hid_recorder_event {
	__u8 packet_count;
	__u8 packet_number;
	__u8 length;
	__u8 data[PACKET_SIZE];
};

/* following are kfuncs exported by HID for HID-BPF */
extern __u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx,
			      unsigned int offset,
			      const size_t __sz) __ksym;

int process_event(struct hid_bpf_ctx *hctx)
{
	unsigned int i, packet_count, length = hctx->size;
	struct hid_recorder_event *event;
	__u8 *data;

	packet_count = length / PACKET_SIZE + 1;

	if (hctx->size < 0 || packet_count > 255)
		return 0;

	for (i = 0; i * PACKET_SIZE < hctx->size && i < HID_MAX_PACKET; i++) {
		data = hid_bpf_get_data(hctx, i * PACKET_SIZE /* offset */, PACKET_SIZE /* size */);
		if (!data)
			return 0; /* EPERM check */

		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (!event)
			return 0;

		event->packet_count = packet_count;
		event->packet_number = i;
		event->length = length;
		__builtin_memcpy(event->data, data, sizeof(event->data));

		bpf_ringbuf_submit(event, 0);
	}

	return 0;
}
