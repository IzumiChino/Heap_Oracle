#if !defined(__linux__)
#error "linux.c built on non-Linux target"
#endif

#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "heap_oracle_hook.h"

int ho_platform_open_writer(struct ho_platform_state *state, const char *name)
{
	void *base;
	int fd;
	int ret;
	size_t len;

	if (!state || !name || name[0] != '/')
		return -EINVAL;

	len = ho_ring_bytes(HO_RING_CAPACITY);
	fd = shm_open(name, O_RDWR, 0);
	if (fd < 0)
		return -errno;

	base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (base == MAP_FAILED)
		return -errno;

	memset(state, 0, sizeof(*state));
	state->mapping = base;
	state->mapping_len = len;

	ret = ho_ring_bind(&state->ring, base, len);
	if (ret) {
		munmap(base, len);
		memset(state, 0, sizeof(*state));
		return ret;
	}

	state->ready = 1;
	return 0;
}

void ho_platform_close_writer(struct ho_platform_state *state)
{
	if (!state || !state->mapping)
		return;

	munmap(state->mapping, state->mapping_len);
	memset(state, 0, sizeof(*state));
}

uint64_t ho_platform_timestamp_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;

	return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

uint32_t ho_platform_process_id(void)
{
	return (uint32_t)getpid();
}

uint32_t ho_platform_thread_id(void)
{
	return (uint32_t)syscall(SYS_gettid);
}

uint32_t ho_platform_capture_callstack(uint64_t *stack, uint32_t depth)
{
	void *frames[HO_STACK_DEPTH];
	uint32_t i;
	int captured;

	if (!stack || !depth)
		return 0;
	if (depth > HO_STACK_DEPTH)
		depth = HO_STACK_DEPTH;

	captured = backtrace(frames, depth);
	if (captured <= 0)
		return 0;

	for (i = 0; i < (uint32_t)captured; i++)
		stack[i] = (uint64_t)(uintptr_t)frames[i];
	for (; i < depth; i++)
		stack[i] = 0;

	return (uint32_t)captured;
}