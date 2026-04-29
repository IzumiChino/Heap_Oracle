#if !defined(_WIN32)
#error "windows.c built on non-Windows target"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processthreadsapi.h>

#include <stdint.h>
#include <string.h>

#include "heap_oracle_hook.h"

static int ho_utf8_to_utf16(const char *src, wchar_t *dst, int dst_len)
{
	int ret;

	ret = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_len);
	if (!ret)
		return -(int)GetLastError();

	return 0;
}

int ho_platform_open_writer(struct ho_platform_state *state, const char *name)
{
	HANDLE mapping;
	void *base;
	int ret;
	size_t len;
	wchar_t wide_name[256];

	if (!state || !name)
		return -1;

	ret = ho_utf8_to_utf16(name, wide_name, 256);
	if (ret)
		return ret;

	len = ho_ring_bytes(HO_RING_CAPACITY);
	mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, wide_name);
	if (!mapping)
		return -(int)GetLastError();

	base = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, len);
	if (!base) {
		ret = -(int)GetLastError();
		CloseHandle(mapping);
		return ret;
	}

	memset(state, 0, sizeof(*state));
	state->handle = mapping;
	state->mapping = base;
	state->mapping_len = len;

	ret = ho_ring_bind(&state->ring, base, len);
	if (ret) {
		UnmapViewOfFile(base);
		CloseHandle(mapping);
		memset(state, 0, sizeof(*state));
		return ret;
	}

	state->ready = 1;
	return 0;
}

void ho_platform_close_writer(struct ho_platform_state *state)
{
	if (!state)
		return;
	if (state->mapping)
		UnmapViewOfFile(state->mapping);
	if (state->handle)
		CloseHandle((HANDLE)state->handle);
	memset(state, 0, sizeof(*state));
}

uint64_t ho_platform_timestamp_ns(void)
{
	LARGE_INTEGER counter;
	LARGE_INTEGER freq;
	uint64_t c, f, sec, rem;

	if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&freq))
		return 0;

	c = (uint64_t)counter.QuadPart;
	f = (uint64_t)freq.QuadPart;
	if (!f)
		return 0;

	/*
	 * Avoid overflow: c * 1e9 overflows uint64 after ~9 seconds when
	 * f ≈ 1 GHz, or ~1844 seconds when f ≈ 10 MHz (typical QPC rate).
	 * Split into whole-second and sub-second parts instead.
	 */
	sec = c / f;
	rem = c % f;
	return sec * 1000000000ULL + rem * 1000000000ULL / f;
}

uint32_t ho_platform_process_id(void)
{
	return GetCurrentProcessId();
}

uint32_t ho_platform_thread_id(void)
{
	return GetCurrentThreadId();
}

uint32_t ho_platform_capture_callstack(uint64_t *stack, uint32_t depth)
{
	USHORT captured;
	uint32_t i;
	void *frames[HO_STACK_DEPTH];

	if (!stack || !depth)
		return 0;
	if (depth > HO_STACK_DEPTH)
		depth = HO_STACK_DEPTH;

	captured = RtlCaptureStackBackTrace(0, (USHORT)depth, frames, NULL);
	for (i = 0; i < captured; i++)
		stack[i] = (uint64_t)(uintptr_t)frames[i];
	for (; i < depth; i++)
		stack[i] = 0;

	return (uint32_t)captured;
}