#include <errno.h>
#include <string.h>

#include "heap_oracle_hook.h"

/* ---------- spinlock helpers (used for MPSC push safety) ---------- */

static void ring_lock_acquire(_Atomic int *lock)
{
	int expected;

	do {
		expected = 0;
	} while (!atomic_compare_exchange_weak_explicit(lock, &expected, 1,
		 memory_order_acquire, memory_order_relaxed));
}

static void ring_lock_release(_Atomic int *lock)
{
	atomic_store_explicit(lock, 0, memory_order_release);
}

size_t ho_ring_bytes(uint32_t capacity)
{
	return sizeof(struct ho_ring_header) +
	       ((size_t)capacity * sizeof(struct ho_event));
}

int ho_ring_init(struct ho_ring_header *hdr, uint32_t capacity)
{
	if (!hdr || !capacity)
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = HO_MAGIC;
	hdr->version = HO_VERSION;
	hdr->capacity = capacity;
	hdr->event_size = sizeof(struct ho_event);
	atomic_init(&hdr->head, 0);
	atomic_init(&hdr->tail, 0);
	atomic_init(&hdr->dropped, 0);

	return 0;
}

int ho_ring_bind(struct ho_ring *ring, void *base, size_t len)
{
	struct ho_ring_header *hdr;
	size_t need;

	if (!ring || !base)
		return -EINVAL;

	hdr = base;
	need = ho_ring_bytes(hdr->capacity);
	if (len < need)
		return -EINVAL;
	if (hdr->magic != HO_MAGIC || hdr->version != HO_VERSION)
		return -EINVAL;
	if (hdr->event_size != sizeof(struct ho_event))
		return -EINVAL;

	ring->hdr = hdr;
	ring->events = (struct ho_event *)((char *)base + sizeof(*hdr));
	ring->capacity = hdr->capacity;
	atomic_init(&ring->push_lock, 0);

	return 0;
}

int ho_ring_push(struct ho_ring *ring, const struct ho_event *event)
{
	struct ho_ring_header *hdr;
	uint64_t head;
	uint64_t tail;
	uint64_t slot;
	int ret = 0;

	if (!ring || !event || !ring->hdr)
		return -EINVAL;

	/*
	 * The hook can be called from multiple threads simultaneously;
	 * each thread has its own ho_tls_guard so re-entrancy from the
	 * *same* thread is prevented, but two *different* threads can
	 * both reach ho_ring_push concurrently.  Without mutual exclusion
	 * the SPSC head-claim/slot-write/head-advance sequence is not
	 * atomic and two producers can overwrite the same slot.
	 * A lightweight spinlock is the safest fix here: it avoids any
	 * heap allocation that a mutex might trigger and contention is
	 * expected to be negligible (most CTF targets are single-threaded
	 * or have low malloc concurrency).
	 */
	ring_lock_acquire(&ring->push_lock);

	hdr = ring->hdr;
	head = atomic_load_explicit(&hdr->head, memory_order_relaxed);
	tail = atomic_load_explicit(&hdr->tail, memory_order_acquire);
	if (head - tail >= ring->capacity) {
		atomic_fetch_add_explicit(&hdr->dropped, 1, memory_order_relaxed);
		ret = -ENOSPC;
		goto out;
	}

	slot = head % ring->capacity;
	ring->events[slot] = *event;
	atomic_store_explicit(&hdr->head, head + 1, memory_order_release);

out:
	ring_lock_release(&ring->push_lock);
	return ret;
}