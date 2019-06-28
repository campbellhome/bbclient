// Copyright (c) 2012-2019 Matt Campbell
// MIT license (see License.txt)

#include "bb.h"

#if BB_ENABLED

#include "bbclient/bb_array.h"
#include <string.h>

// warning C4710: 'int snprintf(char *const ,const std::size_t,const char *const ,...)': function not inlined
BB_WARNING_DISABLE(4710)

#ifndef bba__free
#define bba__free free
#endif

#if bba_log_allocations || bba_log_failed_allocations
#include "bbclient/bb_wrap_stdio.h"
#endif

#if defined(__cplusplus)
extern "C" { // needed to allow inclusion in .cpp unity files
#endif

#if bba_log_allocations
void bba_log_free(void *p, const char *file, int line)
{
	char buf[256];
	if(bb_snprintf(buf, sizeof(buf), "%s(%d) : bba_free(0x%p)\n", file, line, p) < 0) {
		buf[sizeof(buf) - 1] = '\0';
	}
#if BB_USING(BB_COMPILER_MSVC)
	OutputDebugStringA(buf);
#else
	puts(buf);
#endif
}

static BB_INLINE void bba_log_realloc(u64 oldp, void *newp, u64 size, const char *file, int line)
{
	char buf[256];
	if(bb_snprintf(buf, sizeof(buf), "%s(%d) : bba_realloc(0x%016.16" PRIX64 ", 0x%p) %" PRIu64 " bytes\n", file, line, oldp, newp, size) < 0) {
		buf[sizeof(buf) - 1] = '\0';
	}
#if BB_USING(BB_COMPILER_MSVC)
	OutputDebugStringA(buf);
#else
	puts(buf);
#endif
}
#endif // #if bba_log_allocations

#if bba_log_failed_allocations
static BB_INLINE void bba_log_overflowed_realloc(u64 oldp, u32 count, u32 increment, u32 allocated, u32 requested, const char *file, int line)
{
	char buf[256];
	if(bb_snprintf(buf, sizeof(buf), "%s(%d) : bba_realloc(0x%016.16" PRIu64 ") bytes OVERFLOWED - count:%u increment:%u allocated:%u requested:%u\n",
	               file, line, oldp, count, increment, allocated, requested) < 0) {
		buf[sizeof(buf) - 1] = '\0';
	}
#if BB_USING(BB_COMPILER_MSVC)
	OutputDebugStringA(buf);
#else
	puts(buf);
#endif
}
static BB_INLINE void bba_log_failed_realloc(u64 oldp, u64 size, const char *file, int line)
{
	char buf[256];
	if(bb_snprintf(buf, sizeof(buf), "%s(%d) : bba_realloc(0x%016.16" PRIu64 ") %" PRIu64 " bytes FAILED\n", file, line, oldp, size) < 0) {
		buf[sizeof(buf) - 1] = '\0';
	}
#if BB_USING(BB_COMPILER_MSVC)
	OutputDebugStringA(buf);
#else
	puts(buf);
#endif
}
#endif // #if bba_log_failed_allocations

void *bba__raw_add(void *base, ptrdiff_t data_offset, u32 *count, u32 *allocated, u32 increment, u32 itemsize, b32 clear, b32 reserve_only, const char *file, int line)
{
	void **parr = (void **)((u8 *)base + data_offset);
	void *arr = *parr;

	BB_UNUSED(file);
	BB_UNUSED(line);

	if(*count + increment > *allocated) {
		u32 dbl_cur = 2 * *allocated;
		u32 min_needed = *count + increment;
		u32 desired = dbl_cur > min_needed ? dbl_cur : min_needed;

		if(itemsize * desired > itemsize * *allocated) {
			void *p = (void *)bba__realloc(arr, itemsize * (u64)desired);
			if(p) {
				void *ret = (u8 *)p + itemsize * (u64)*count;
#if bba_log_allocations
				bba_log_realloc((u64)arr, p, itemsize * desired, file, line);
#endif
				if(clear && !reserve_only) {
					u32 bytes = itemsize * (desired - *allocated);
					memset(ret, 0, bytes);
				}
				*parr = p;
				*allocated = desired;
				if(!reserve_only) {
					*count += increment;
				}
				return ret;
			} else {
#if bba_log_failed_allocations
				bba_log_failed_realloc((u64)arr, itemsize * desired, file, line);
#endif
				return NULL;
			}
		} else {
#if bba_log_failed_allocations
			bba_log_overflowed_realloc((u64)arr, *count, increment, *allocated, itemsize * desired, file, line);
#endif
			return NULL;
		}
	} else {
		void *ret = (u8 *)arr + itemsize * (u64)*count;
		if(!reserve_only) {
			if(clear) {
				u32 bytes = itemsize * increment;
				memset(ret, 0, bytes);
			}
			*count += increment;
		}
		return ret;
	}
}

#if defined(__cplusplus)
}
#endif

#endif // #if BB_ENABLED
