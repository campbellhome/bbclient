// Copyright (c) 2012-2019 Matt Campbell
// MIT license (see License.txt)

#include "bb.h"

#if BB_ENABLED

#include "bbclient/bb_file.h"

#if BB_USING(BB_COMPILER_MSVC)

#include <Windows.h>

bb_file_handle_t bb_file_open_for_write(const char *pathname)
{
	// TODO: update calling code to check for a BB_INVALID_FILE_HANDLE which can be ~0u on windows
	bb_file_handle_t handle = CreateFileA(pathname, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(handle == INVALID_HANDLE_VALUE) {
		handle = 0;
	}
	return handle;
}

bb_file_handle_t bb_file_open_for_read(const char *pathname)
{
	// TODO: update calling code to check for a BB_INVALID_FILE_HANDLE which can be ~0u on windows
	bb_file_handle_t handle = CreateFileA(pathname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(handle == INVALID_HANDLE_VALUE) {
		handle = 0;
	}
	return handle;
}

u32 bb_file_write(bb_file_handle_t handle, void *data, u32 dataLen)
{
	DWORD written = 0;
	if(handle) {
		WriteFile(handle, data, dataLen, &written, NULL);
	}
	return written;
}

u32 bb_file_read(bb_file_handle_t handle, void *buffer, u32 bufferSize)
{
	DWORD bytesRead = 0;
	BOOL res = ReadFile(handle, buffer, bufferSize, &bytesRead, NULL);
	if(!res) {
		// error
	}
	return bytesRead;
}

u32 bb_file_size(bb_file_handle_t handle)
{
#if BB_USING(BB_PLATFORM_DURANGO)
	BB_UNUSED(handle);
	return 0;
#else  // #if BB_USING(BB_PLATFORM_DURANGO)
	DWORD fileSizeHi = 0;
	DWORD fileSize = GetFileSize(handle, &fileSizeHi);
	return fileSize;
#endif // #else // #if BB_USING(BB_PLATFORM_DURANGO)
}

void bb_file_close(bb_file_handle_t handle)
{
	if(handle) {
		CloseHandle(handle);
	}
}

void bb_file_flush(bb_file_handle_t handle)
{
	if(handle) {
		FlushFileBuffers(handle);
	}
}

#else // #if BB_USING(BB_COMPILER_MSVC)

#include "bbclient/bb_wrap_stdio.h"

bb_file_handle_t bb_file_open_for_write(const char *pathname)
{
	return fopen(pathname, "wb");
}

bb_file_handle_t bb_file_open_for_read(const char *pathname)
{
	return fopen(pathname, "rb");
}

u32 bb_file_write(bb_file_handle_t handle, void *data, u32 dataLen)
{
	u32 written = 0;
	if(handle) {
		FILE *fp = (FILE *)handle;
		written = (u32)fwrite(data, 1, dataLen, fp);
	}
	return written;
}

u32 bb_file_read(bb_file_handle_t handle, void *buffer, u32 bufferSize)
{
	return (u32)fread(buffer, 1, bufferSize, (FILE *)handle);
}

u32 bb_file_size(bb_file_handle_t handle)
{
	FILE *fp = (FILE *)handle;
	long curPos = ftell(fp);
	fseek(fp, 0, SEEK_END);
	long fileSize32 = ftell(fp);
	fseek(fp, curPos, SEEK_SET);
	return fileSize32 > 0 ? (u32)fileSize32 : 0u;
}

void bb_file_close(bb_file_handle_t handle)
{
	if(handle) {
		FILE *fp = (FILE *)handle;
		fclose(fp);
	}
}

void bb_file_flush(bb_file_handle_t handle)
{
	if(handle) {
		FILE *fp = (FILE *)handle;
		fflush(fp);
	}
}

#endif // #else #endif // #if BB_USING(BB_COMPILER_MSVC)

b32 bb_file_readable(const char *pathname)
{
	bb_file_handle_t handle = bb_file_open_for_read(pathname);
	if(handle) {
		bb_file_close(handle);
	}
	return handle != 0;
}

#endif // #if BB_ENABLED
