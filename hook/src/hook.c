#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "heap_oracle_hook.h"

#if defined(__linux__)
extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t n, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void __libc_free(void *ptr);
#endif

struct ho_hooks {
	void *(*malloc_fn)(size_t size);
	void *(*calloc_fn)(size_t n, size_t size);
	void *(*realloc_fn)(void *ptr, size_t size);
	void (*free_fn)(void *ptr);
	int (*posix_memalign_fn)(void **memptr, size_t alignment, size_t size);
	void *(*aligned_alloc_fn)(size_t alignment, size_t size);
};

static struct ho_hooks ho_hooks;
static struct ho_platform_state ho_platform;
static _Atomic int ho_initialized;
static _Atomic int ho_trace_enabled;
static __thread unsigned int ho_tls_guard;
/*
 * One-shot init gate: 0 = not started, 1 = taken.
 * CAS 0→1 to become the sole initialiser thread; all other threads
 * that lose the race simply skip initialisation and return early.
 * This prevents concurrent writes to the global ho_platform struct.
 */
static _Atomic int ho_init_once;

/*
 * --main-only filtering: when the HEAP_ORACLE_MAIN_ONLY=1 env var is
 * set, events emitted before the user's main() are suppressed.
 * ho_main_entered is set by the __libc_start_main wrapper on Linux.
 */
static _Atomic int ho_main_entered;
static int ho_filter_pre_main;
#if defined(__linux__)
static int (*ho_saved_main)(int, char **, char **);
#endif

static void ho_resolve_symbols(void)
{
	ho_hooks.malloc_fn = dlsym(RTLD_NEXT, "malloc");
	ho_hooks.calloc_fn = dlsym(RTLD_NEXT, "calloc");
	ho_hooks.realloc_fn = dlsym(RTLD_NEXT, "realloc");
	ho_hooks.free_fn = dlsym(RTLD_NEXT, "free");
	ho_hooks.posix_memalign_fn = dlsym(RTLD_NEXT, "posix_memalign");
	ho_hooks.aligned_alloc_fn = dlsym(RTLD_NEXT, "aligned_alloc");
}

static void *ho_fallback_malloc(size_t size)
{
#if defined(__linux__)
	return __libc_malloc(size);
#else
	return ho_hooks.malloc_fn ? ho_hooks.malloc_fn(size) : NULL;
#endif
}

static void *ho_fallback_calloc(size_t n, size_t size)
{
#if defined(__linux__)
	return __libc_calloc(n, size);
#else
	return ho_hooks.calloc_fn ? ho_hooks.calloc_fn(n, size) : NULL;
#endif
}

static void *ho_fallback_realloc(void *ptr, size_t size)
{
#if defined(__linux__)
	return __libc_realloc(ptr, size);
#else
	return ho_hooks.realloc_fn ? ho_hooks.realloc_fn(ptr, size) : NULL;
#endif
}

static void ho_fallback_free(void *ptr)
{
#if defined(__linux__)
	__libc_free(ptr);
#else
	if (ho_hooks.free_fn)
		ho_hooks.free_fn(ptr);
#endif
}

static void ho_fill_event(struct ho_event *event, uint16_t kind, uint64_t addr,
			 uint64_t aux_addr, uint64_t size, uint64_t aux_size)
{
	uint32_t depth;

	memset(event, 0, sizeof(*event));
	event->kind = kind;
	event->addr = addr;
	event->aux_addr = aux_addr;
	event->size = size;
	event->aux_size = aux_size;
	event->pid = ho_platform_process_id();
	event->tid = ho_platform_thread_id();
	event->timestamp_ns = ho_platform_timestamp_ns();

	depth = ho_platform_capture_callstack(event->callstack, HO_STACK_DEPTH);
	event->stack_len = depth;
	if (depth)
		event->flags |= HO_EVENT_FLAG_STACK_VALID;
	if (depth >= HO_STACK_DEPTH)
		event->flags |= HO_EVENT_FLAG_STACK_TRUNCATED;
}

static void ho_publish(uint16_t kind, uint64_t addr, uint64_t aux_addr,
		      uint64_t size, uint64_t aux_size)
{
	struct ho_event event;

	if (!atomic_load_explicit(&ho_trace_enabled, memory_order_acquire))
		return;

	/* When --main-only filtering is active, suppress pre-main events */
	if (ho_filter_pre_main &&
	    !atomic_load_explicit(&ho_main_entered, memory_order_acquire))
		return;

	ho_fill_event(&event, kind, addr, aux_addr, size, aux_size);
	ho_ring_push(&ho_platform.ring, &event);
}

static void ho_try_enable_trace(void)
{
	const char *name;
	int expected = 0;

	/* Fast path: already fully initialised. */
	if (atomic_load_explicit(&ho_initialized, memory_order_acquire))
		return;

	/*
	 * Race to become the one initialising thread.
	 * If the CAS fails another thread is (or was) already initialising;
	 * return early rather than spinning — the losing thread's hook call
	 * will simply be a no-op until ho_initialized becomes visible.
	 * This is safe: events emitted before the ring is ready are lost,
	 * which is acceptable since the consumer side isn't ready yet either.
	 */
	if (!atomic_compare_exchange_strong_explicit(&ho_init_once, &expected, 1,
			memory_order_acquire, memory_order_relaxed))
		return;

	ho_tls_guard++;
	ho_resolve_symbols();
	{
		const char *main_only = getenv("HEAP_ORACLE_MAIN_ONLY");
		if (main_only && main_only[0] == '1')
			ho_filter_pre_main = 1;
	}
	name = getenv("HEAP_ORACLE_SHM_NAME");
	if (name && !ho_platform_open_writer(&ho_platform, name))
		atomic_store_explicit(&ho_trace_enabled, 1, memory_order_release);
	atomic_store_explicit(&ho_initialized, 1, memory_order_release);
	ho_tls_guard--;
}

__attribute__((constructor)) static void ho_ctor(void)
{
	ho_try_enable_trace();
}

__attribute__((destructor)) static void ho_dtor(void)
{
	ho_platform_close_writer(&ho_platform);
}

void *malloc(size_t size)
{
	void *ret;

	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (ho_tls_guard)
		return ho_hooks.malloc_fn ? ho_hooks.malloc_fn(size) : ho_fallback_malloc(size);

	ho_tls_guard++;
	ret = ho_hooks.malloc_fn ? ho_hooks.malloc_fn(size) : ho_fallback_malloc(size);
	ho_publish(HO_EVENT_ALLOC, (uint64_t)(uintptr_t)ret, 0, size, 0);
	ho_tls_guard--;

	return ret;
}

void *calloc(size_t n, size_t size)
{
	void *ret;
	uint64_t total = 0;

	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (ho_tls_guard)
		return ho_hooks.calloc_fn ? ho_hooks.calloc_fn(n, size) : ho_fallback_calloc(n, size);

	ho_tls_guard++;
	ret = ho_hooks.calloc_fn ? ho_hooks.calloc_fn(n, size) : ho_fallback_calloc(n, size);
	if (!__builtin_mul_overflow((uint64_t)n, (uint64_t)size, &total))
		ho_publish(HO_EVENT_CALLOC, (uint64_t)(uintptr_t)ret, 0, total, n);
	else
		ho_publish(HO_EVENT_CALLOC, (uint64_t)(uintptr_t)ret, 0, 0, n);
	ho_tls_guard--;

	return ret;
}

void free(void *ptr)
{
	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (ho_tls_guard) {
		ho_hooks.free_fn ? ho_hooks.free_fn(ptr) : ho_fallback_free(ptr);
		return;
	}

	ho_tls_guard++;
	ho_publish(HO_EVENT_FREE, (uint64_t)(uintptr_t)ptr, 0, 0, 0);
	ho_hooks.free_fn ? ho_hooks.free_fn(ptr) : ho_fallback_free(ptr);
	ho_tls_guard--;
}

void *realloc(void *ptr, size_t size)
{
	void *ret;

	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (ho_tls_guard)
		return ho_hooks.realloc_fn ? ho_hooks.realloc_fn(ptr, size) : ho_fallback_realloc(ptr, size);

	ho_tls_guard++;
	ret = ho_hooks.realloc_fn ? ho_hooks.realloc_fn(ptr, size) : ho_fallback_realloc(ptr, size);
	ho_publish(HO_EVENT_REALLOC, (uint64_t)(uintptr_t)ret,
		   (uint64_t)(uintptr_t)ptr, size, 0);
	ho_tls_guard--;

	return ret;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	void *ptr = NULL;

	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (!ho_hooks.posix_memalign_fn)
		return ENOSYS; /* POSIX: return error code directly, do not set errno */
	if (ho_tls_guard)
		return ho_hooks.posix_memalign_fn(memptr, alignment, size);

	ho_tls_guard++;
	ret = ho_hooks.posix_memalign_fn(memptr, alignment, size);
	if (!ret && memptr)
		ptr = *memptr;
	ho_publish(HO_EVENT_MEMALIGN, (uint64_t)(uintptr_t)ptr, 0, size, alignment);
	ho_tls_guard--;

	return ret;
}

void *aligned_alloc(size_t alignment, size_t size)
{
	void *ret;

	if (!atomic_load_explicit(&ho_initialized, memory_order_acquire))
		ho_try_enable_trace();
	if (!ho_hooks.aligned_alloc_fn)
		return NULL;
	if (ho_tls_guard)
		return ho_hooks.aligned_alloc_fn(alignment, size);

	ho_tls_guard++;
	ret = ho_hooks.aligned_alloc_fn(alignment, size);
	ho_publish(HO_EVENT_MEMALIGN, (uint64_t)(uintptr_t)ret, 0, size, alignment);
	ho_tls_guard--;

	return ret;
}

/* ------------------------------------------------------------------ */
/* __libc_start_main interposition (Linux only)                       */
/*                                                                    */
/* We replace the user's main with a thin wrapper that sets            */
/* ho_main_entered = 1 right before calling the real main().           */
/* This lets ho_publish() suppress all init-time allocations when      */
/* HEAP_ORACLE_MAIN_ONLY=1 is set.                                    */
/*                                                                    */
/* Call chain:  _start → our __libc_start_main → real __libc_start_   */
/* main(ho_main_wrapper, ...) → .init/.ctors → ho_main_wrapper →      */
/* real main().                                                        */
/* ------------------------------------------------------------------ */
#if defined(__linux__)

typedef int (*ho_start_main_t)(
	int (*)(int, char **, char **),
	int, char **,
	void (*)(void), void (*)(void),
	void (*)(void), void *);

static int ho_main_wrapper(int argc, char **argv, char **envp)
{
	atomic_store_explicit(&ho_main_entered, 1, memory_order_release);
	return ho_saved_main(argc, argv, envp);
}

int __libc_start_main(
	int (*main_fn)(int, char **, char **),
	int argc, char **argv,
	void (*init)(void), void (*fini)(void),
	void (*rtld_fini)(void), void *stack_end)
{
	ho_start_main_t real;

	ho_saved_main = main_fn;
	real = (ho_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
	if (!real)
		_exit(127);
	return real(ho_main_wrapper, argc, argv, init, fini, rtld_fini,
		    stack_end);
}

#endif /* __linux__ */