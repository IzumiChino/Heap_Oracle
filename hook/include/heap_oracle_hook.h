#ifndef HEAP_ORACLE_H
#define HEAP_ORACLE_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define HO_MAGIC 0x484f5243U
#define HO_VERSION 1U
#define HO_STACK_DEPTH 8U
#define HO_RING_CAPACITY 4096U

enum ho_event_kind {
	HO_EVENT_INVALID = 0,
	HO_EVENT_ALLOC = 1,
	HO_EVENT_FREE = 2,
	HO_EVENT_REALLOC = 3,
	HO_EVENT_MEMALIGN = 4,
	HO_EVENT_CALLOC = 5,
};

enum ho_event_flags {
	HO_EVENT_FLAG_STACK_VALID = 1U << 0,
	HO_EVENT_FLAG_STACK_TRUNCATED = 1U << 1,
};

struct ho_event {
	uint16_t kind;
	uint16_t flags;
	uint32_t pid;
	uint32_t tid;
	uint32_t stack_len;
	uint64_t timestamp_ns;
	uint64_t addr;
	uint64_t aux_addr;
	uint64_t size;
	uint64_t aux_size;
	uint64_t callstack[HO_STACK_DEPTH];
};

struct ho_ring_header {
	uint32_t magic;
	uint32_t version;
	uint32_t capacity;
	uint32_t event_size;
	_Atomic uint64_t head;
	_Atomic uint64_t tail;
	_Atomic uint64_t dropped;
};

struct ho_ring {
	struct ho_ring_header *hdr;
	struct ho_event *events;
	uint32_t capacity;
	/* Spinlock protecting concurrent producers (MPSC safety).
	 * Lives in the C-side handle only; not part of shared memory. */
	_Atomic int push_lock;
};

struct ho_platform_state {
	void *mapping;
	void *handle;
	size_t mapping_len;
	struct ho_ring ring;
	int ready;
};

size_t ho_ring_bytes(uint32_t capacity);
int ho_ring_init(struct ho_ring_header *hdr, uint32_t capacity);
int ho_ring_bind(struct ho_ring *ring, void *base, size_t len);
int ho_ring_push(struct ho_ring *ring, const struct ho_event *event);

int ho_platform_open_writer(struct ho_platform_state *state, const char *name);
void ho_platform_close_writer(struct ho_platform_state *state);
uint64_t ho_platform_timestamp_ns(void);
uint32_t ho_platform_process_id(void);
uint32_t ho_platform_thread_id(void);
uint32_t ho_platform_capture_callstack(uint64_t *stack, uint32_t depth);

#endif