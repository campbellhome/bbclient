// Copyright (c) 2012-2019 Matt Campbell
// MIT license (see License.txt)

#if defined(_MSC_VER)
__pragma(warning(disable : 4710)); // warning C4710 : 'int printf(const char *const ,...)' : function not inlined
#endif

#include "bb.h"

#if BB_ENABLED

#include "bbclient/bb_array.h"
#include "bbclient/bb_connection.h"
#include "bbclient/bb_criticalsection.h"
#include "bbclient/bb_discovery_client.h"
#include "bbclient/bb_file.h"
#include "bbclient/bb_log.h"
#include "bbclient/bb_packet.h"
#include "bbclient/bb_string.h"
#include "bbclient/bb_time.h"
#include "bbclient/bb_wrap_stdio.h"
#include <stdlib.h>
#include <wchar.h>

#if BB_USING(BB_COMPILER_MSVC)
#define bb_thread_local __declspec(thread)
u64 bb_get_current_thread_id(void)
{
	return GetCurrentThreadId();
}
#else // #if BB_USING(BB_COMPILER_MSVC)
#define bb_thread_local __thread
#if BB_USING(BB_PLATFORM_LINUX)
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#endif // #if BB_USING(BB_PLATFORM_LINUX)
u64 bb_get_current_thread_id(void)
{
#if BB_USING(BB_PLATFORM_LINUX)
	return syscall(SYS_gettid);
#else  // #if BB_USING(BB_PLATFORM_LINUX)
	return (u64)pthread_self();
#endif // #else // #if BB_USING(BB_PLATFORM_LINUX)
}
#endif // #else // #if BB_USING(BB_COMPILER_MSVC)

typedef struct bb_id_s {
	char text[1020];
	u32 id;
} bb_id_t;
typedef struct bb_ids_s {
	u32 count;
	u32 allocated;
	bb_id_t *data;
	u32 lastId;
	u8 pad[4];
} bb_ids_t;

static bb_ids_t s_bb_categoryIds;
static bb_ids_t s_bb_pathIds;
static bb_connection_t s_con;
static bb_critical_section s_id_cs;
static bb_file_handle_t s_fp;
static u64 s_lastFileFlushTime;
u32 g_bb_initFlags;
static bb_write_callback s_bb_write_callback;
static void *s_bb_write_callback_context;
static bb_flush_callback s_bb_flush_callback;
static void *s_bb_flush_callback_context;
static bb_send_callback s_bb_send_callback;
static void *s_bb_send_callback_context;
static bb_incoming_console_command_handler s_bb_console_command_handler;
static void *s_bb_console_command_context;

typedef struct bbtraceBuffer_s {
	char packetBuffer[16 * 1024];
#if BB_COMPILE_WIDECHAR
	bb_wchar_t wideBuffer[16 * 1024];
#endif
} bbtraceBuffer_t;

static bb_thread_local bbtraceBuffer_t *s_bb_trace_packet_buffer;
static bb_thread_local bb_colors_t s_bb_colors;
void bb_set_color(bb_color_t fg, bb_color_t bg)
{
	bb_trace_partial_end();
	s_bb_colors.fg = fg;
	s_bb_colors.bg = bg;
}

enum {
	kBBFile_FlushIntervalMillis = 500,
};

#if BB_COMPILE_WIDECHAR && !(defined(BB_USER_WCSTOMBCS) && BB_USER_WCSTOMBCS)
enum { kBB_WCSToMBCS_NumSlots = 4 };
typedef struct
{
	size_t next;
	char buffer[kBB_WCSToMBCS_NumSlots][2048];
} bb_wcstombcs_data_t;
static bb_thread_local bb_wcstombcs_data_t s_bb_wcstombcs_data;

static BB_INLINE const char *bb_wcstombcs(const bb_wchar_t *wstr)
{
	char *buffer = s_bb_wcstombcs_data.buffer[s_bb_wcstombcs_data.next++ % kBB_WCSToMBCS_NumSlots];
	size_t bufferSize = sizeof(s_bb_wcstombcs_data.buffer[0]);
	buffer[0] = '\0';
#if BB_USING(BB_COMPILER_MSVC)
	size_t numCharsConverted;
	wcstombs_s(&numCharsConverted, buffer, bufferSize, wstr, _TRUNCATE);
#else
	wcstombs(buffer, wstr, bufferSize);
	buffer[bufferSize - 1] = '\0';
#endif
	return buffer;
}

static BB_INLINE const char *bb_wcstombcs_inline(const bb_wchar_t *wstr, char *buffer, size_t bufferSize, size_t *numCharsConverted)
{
	buffer[0] = '\0';
#if BB_USING(BB_COMPILER_MSVC)
	wcstombs_s(numCharsConverted, buffer, bufferSize, wstr, _TRUNCATE);
#else
	*numCharsConverted = 1 + wcstombs(buffer, wstr, bufferSize);
	if(*numCharsConverted) {
		buffer[*numCharsConverted - 1] = '\0';
	}
#endif
	return buffer;
}

#endif // #if BB_COMPILE_WIDECHAR && !(defined(BB_USER_WCSTOMBCS) && BB_USER_WCSTOMBCS)

static BB_INLINE void bb_fill_header(bb_decoded_packet_t *decoded, bb_packet_type_e packetType, u32 pathId, u32 line)
{
	decoded->type = packetType;
	decoded->header.timestamp = bb_current_ticks();
	decoded->header.threadId = bb_get_current_thread_id();
	decoded->header.fileId = pathId;
	decoded->header.line = line;
}

static BB_INLINE void bb_send(bb_decoded_packet_t *decoded)
{
	if(s_bb_send_callback) {
		(*s_bb_send_callback)(s_bb_send_callback_context, decoded);
	}
	if(s_fp || s_bb_write_callback) {
		u8 buf[BB_MAX_PACKET_BUFFER_SIZE];
		u16 serializedLen = bbpacket_serialize(decoded, buf + 2, sizeof(buf) - 2);
		if(serializedLen) {
			serializedLen += 2;
			buf[0] = (u8)(serializedLen >> 8);
			buf[1] = (u8)(serializedLen & 0xFF);
			if(s_bb_write_callback) {
				(*s_bb_write_callback)(s_bb_write_callback_context, buf, serializedLen);
			}
			if(s_fp) {
				bb_file_write(s_fp, buf, serializedLen);
			}
		} else {
			bb_error("bb_send failed to encode packet");
		}
	}
	bbcon_send(&s_con, decoded);
}

bb_platform_e bb_platform(void)
{
#if BB_USING(BB_PLATFORM_WINDOWS)
	return kBBPlatform_Windows;
#elif BB_USING(BB_PLATFORM_LINUX)
	return kBBPlatform_Linux;
#elif BB_USING(BB_PLATFORM_ANDROID)
	return kBBPlatform_Android;
#elif BB_USING(BB_PLATFORM_ORBIS)
	return kBBPlatform_Orbis;
#elif BB_USING(BB_PLATFORM_DURANGO)
	return kBBPlatform_Durango;
#elif BB_USING(BB_PLATFORM_NX)
	return kBBPlatform_Nx;
#else
	BB_ASSERT(false);
	return kBBPlatform_Unknown;
#endif
}

static const char *s_bb_platformNames[] = {
	"Unknown",  // kBBPlatform_Unknown,
	"Windows",  // kBBPlatform_Windows,
	"Linux",    // kBBPlatform_Linux,
	"Android",  // kBBPlatform_Android,
	"PS4",      // kBBPlatform_Orbis,
	"Xbox One", // kBBPlatform_Durango,
	"Switch",   // kBBPlatform_Nx,
};
BB_CTASSERT(BB_ARRAYSIZE(s_bb_platformNames) == kBBPlatform_Count);

const char *bb_platform_name(bb_platform_e platform)
{
	platform = (platform < kBBPlatform_Count) ? platform : kBBPlatform_Unknown;
	return s_bb_platformNames[platform];
}

void bb_init_file(const char *path)
{
	if(!s_fp) {
		s_fp = bb_file_open_for_write(path);
	}
}

#if BB_COMPILE_WIDECHAR
void bb_init_file_w(const bb_wchar_t *path)
{
	bb_init_file(bb_wcstombcs(path));
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_init(const char *applicationName, const char *sourceApplicationName, u32 sourceIp, u32 initFlags)
{
	b32 sendAppInfo = s_fp != NULL || s_bb_write_callback != NULL;
	if(!sourceApplicationName) {
		sourceApplicationName = "";
	}
	g_bb_initFlags = initFlags;
	bb_critical_section_init(&s_id_cs);
	bb_log_init();
	bbcon_init(&s_con);
	s_con.flags |= kBBCon_Blackbox;
	if(bbnet_init() && (initFlags & kBBInitFlag_NoDiscovery) == 0) {
		bb_discovery_result_t discovery = bb_discovery_client_start(applicationName, sourceApplicationName,
		                                                            sourceIp, 0, 0);
		if(discovery.serverIp) {
#if 1
			if(bbcon_connect_client_async(&s_con, discovery.serverIp, discovery.serverPort)) {
				while(bbcon_is_connecting(&s_con)) {
					bbcon_tick_connecting(&s_con);
				}
				if(bbcon_is_connected(&s_con)) {
					sendAppInfo = true;
				}
			}
#else
			if(bbcon_connect_client(&s_con, discovery.serverIp, discovery.serverPort, 5)) {
				sendAppInfo = true;
			}
#endif
		}
	}

	if(sendAppInfo) {
		// connected - send any initial packets such as application name :)
		bb_decoded_packet_t decoded;
		decoded.type = kBBPacketType_AppInfo;
		decoded.header.timestamp = bb_current_ticks();
		decoded.header.threadId = bb_get_current_thread_id();
		decoded.header.fileId = 0;
		decoded.header.line = 0;
		decoded.packet.appInfo.initialTimestamp = decoded.header.timestamp;
		decoded.packet.appInfo.millisPerTick = bb_millis_per_tick();
		decoded.packet.appInfo.initFlags = initFlags;
		decoded.packet.appInfo.platform = bb_platform();
		decoded.packet.appInfo.microsecondsFromEpoch = bb_current_time_microseconds_from_epoch();
		bb_strncpy(decoded.packet.appInfo.applicationName, applicationName, sizeof(decoded.packet.appInfo.applicationName));
		bb_send(&decoded);
	}
}

#if BB_COMPILE_WIDECHAR
void bb_init_w(const bb_wchar_t *applicationName, const bb_wchar_t *sourceApplicationName, uint32_t sourceIp, bb_init_flags_t initFlags)
{
	if(!sourceApplicationName) {
		sourceApplicationName = BB_WCHARS("");
	}
	bb_init(bb_wcstombcs(applicationName), bb_wcstombcs(sourceApplicationName), sourceIp, initFlags);
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_shutdown(const char *file, int line)
{
	uint32_t bb_path_id = 0;
	bb_resolve_path_id(file, &bb_path_id, (uint32_t)line);
	bb_thread_end(bb_path_id, line);
	if(s_fp) {
		bb_file_close(s_fp);
		s_fp = NULL;
	}
	bbcon_flush(&s_con);
	bbcon_shutdown(&s_con);
	bbnet_shutdown();
	bb_log_shutdown();
	bb_critical_section_shutdown(&s_id_cs);
	bba_free(s_bb_categoryIds);
	bba_free(s_bb_pathIds);
	if(s_bb_trace_packet_buffer) {
		free(s_bb_trace_packet_buffer);
		s_bb_trace_packet_buffer = NULL;
	}
}

int bb_is_connected(void)
{
	return bbcon_is_connected(&s_con);
}

void bb_tick(void)
{
	bb_decoded_packet_t decoded;
	bbcon_tick(&s_con);
	if(s_fp || s_bb_flush_callback) {
		u64 now = bb_current_time_ms();
		if(now > s_lastFileFlushTime + kBBFile_FlushIntervalMillis) {
			if(s_bb_flush_callback) {
				(*s_bb_flush_callback)(s_bb_flush_callback_context);
			}
			if(s_fp) {
				bb_file_flush(s_fp);
			}
		}
	}
	while(bbcon_decodePacket(&s_con, &decoded)) {
		// handle server->client packet here - callback to application
		if(decoded.type == kBBPacketType_ConsoleCommand && s_bb_console_command_handler) {
			(*s_bb_console_command_handler)(decoded.packet.consoleCommand.text, s_bb_console_command_context);
		}
	}
}

void bb_flush(void)
{
	if(s_bb_flush_callback) {
		(*s_bb_flush_callback)(s_bb_flush_callback_context);
	}
	if(s_fp) {
		bb_file_flush(s_fp);
	}
	bbcon_flush(&s_con);
}

void bb_echo_to_stdout(void *context, bb_decoded_packet_t *decoded)
{
	BB_UNUSED(context);
	if(bbpacket_is_log_text_type(decoded->type) || decoded->type == kBBPacketType_LogText) {
		switch(decoded->packet.logText.level) {
		case kBBLogLevel_Warning:
		case kBBLogLevel_Error:
		case kBBLogLevel_Fatal:
			fputs(decoded->packet.logText.text, stderr);
#if BB_USING(BB_PLATFORM_WINDOWS)
			OutputDebugStringA(decoded->packet.logText.text);
#endif
			break;

		case kBBLogLevel_Log:
		case kBBLogLevel_Display:
			fputs(decoded->packet.logText.text, stdout);
#if BB_USING(BB_PLATFORM_WINDOWS)
			OutputDebugStringA(decoded->packet.logText.text);
#endif
			break;

		default:
#if BB_USING(BB_PLATFORM_WINDOWS)
			OutputDebugStringA(decoded->packet.logText.text);
#endif
			break;
		}
	}
}

void bb_set_write_callback(bb_write_callback callback, void *context)
{
	s_bb_write_callback = callback;
	s_bb_write_callback_context = context;
}

void bb_set_flush_callback(bb_flush_callback callback, void *context)
{
	s_bb_flush_callback = callback;
	s_bb_flush_callback_context = context;
}

void bb_set_send_callback(bb_send_callback callback, void *context)
{
	s_bb_send_callback = callback;
	s_bb_send_callback_context = context;
}

void bb_set_incoming_console_command_handler(bb_incoming_console_command_handler handler, void *context)
{
	s_bb_console_command_handler = handler;
	s_bb_console_command_context = context;
}

void bb_thread_start(uint32_t pathId, uint32_t line, const char *name)
{
	bb_decoded_packet_t decoded;
	bb_fill_header(&decoded, kBBPacketType_ThreadStart, pathId, line);
	bb_strncpy(decoded.packet.threadStart.text, name, sizeof(decoded.packet.threadStart.text));
	bb_send(&decoded);
}

#if BB_COMPILE_WIDECHAR
void bb_thread_start_w(uint32_t pathId, uint32_t line, const bb_wchar_t *name)
{
	bb_thread_start(pathId, line, bb_wcstombcs(name));
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_thread_set_name(uint32_t pathId, uint32_t line, const char *name)
{
	bb_decoded_packet_t decoded;
	bb_fill_header(&decoded, kBBPacketType_ThreadName, pathId, line);
	bb_strncpy(decoded.packet.threadName.text, name, sizeof(decoded.packet.threadName.text));
	bb_send(&decoded);
}

#if BB_COMPILE_WIDECHAR
void bb_thread_set_name_w(uint32_t pathId, uint32_t line, const bb_wchar_t *name)
{
	bb_thread_set_name(pathId, line, bb_wcstombcs(name));
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_thread_end(uint32_t pathId, uint32_t line)
{
	bb_decoded_packet_t decoded;
	bb_fill_header(&decoded, kBBPacketType_ThreadEnd, pathId, line);
	bb_send(&decoded);
	if(s_bb_trace_packet_buffer) {
		free(s_bb_trace_packet_buffer);
		s_bb_trace_packet_buffer = NULL;
	}
}

static u32 bb_find_id(const char *text, bb_ids_t *ids)
{
	u32 i;
	for(i = 0; i < ids->count; ++i) {
		bb_id_t *id = ids->data + i;
		if(!strcmp(id->text, text)) {
			return id->id;
		}
	}
	return 0;
}

static u32 bb_resolve_id(const char *name, bb_ids_t *ids, u32 pathId, u32 line, bb_packet_type_e packetType, size_t maxSize, b32 recurse)
{
	bb_decoded_packet_t decoded;
	u32 existing = bb_find_id(name, ids);
	if(existing) {
		return existing;
	} else {
		// need to add parent categories also on the client here so they can get proper ids
		if(packetType == kBBPacketType_CategoryId && recurse) {
			char categoryBuf[kBBSize_Category];
			char *c = categoryBuf;
			const char *s = name;
			while(*s && c - categoryBuf < kBBSize_Category) {
				if(s[0] == ':' && s[1] == ':') {
					*c = '\0';
					bb_resolve_id(categoryBuf, ids, pathId, line, packetType, maxSize, false);
					*c++ = *s++;
				}
				*c++ = *s++;
			}
		}

		{
			u32 newId = ++ids->lastId;
			bb_id_t *newIdData = bba_add(*ids, 1);
			//u32 tmp;
			//for(tmp = 0; tmp < 1000; ++tmp) {
			//	newIdData = bba_add(*ids, 1);
			//}
			if(newIdData) {
				newIdData->id = newId;
				bb_strncpy(newIdData->text, name, sizeof(newIdData->text));
			}
			bb_fill_header(&decoded, packetType, (pathId) ? pathId : newId, line);
			decoded.packet.registerId.id = newId;
			bb_strncpy(decoded.packet.registerId.name, name, BB_MIN(maxSize, sizeof(decoded.packet.registerId.name)));
			bb_send(&decoded);
			return newId;
		}
	}
}

uint32_t bb_resolve_ids(const char *path, const char *category, uint32_t *pathId, uint32_t *categoryId, uint32_t line)
{
	if(!s_id_cs.initialized)
		return 0;
	bb_critical_section_lock(&s_id_cs);
	if(!*pathId) {
		*pathId = bb_resolve_id(path, &s_bb_pathIds, 0, line, kBBPacketType_FileId, ~0U, false);
	}
	if(!*categoryId) {
		*categoryId = bb_resolve_id(category, &s_bb_categoryIds, *pathId, line, kBBPacketType_CategoryId, kBBSize_Category, true);
	}
	bb_critical_section_unlock(&s_id_cs);
	return 1;
}

#if BB_COMPILE_WIDECHAR
uint32_t bb_resolve_ids_w(const char *path, const bb_wchar_t *category, uint32_t *pathId, uint32_t *categoryId, uint32_t line)
{
	return bb_resolve_ids(path, bb_wcstombcs(category), pathId, categoryId, line);
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_resolve_path_id(const char *path, uint32_t *pathId, uint32_t line)
{
	if(!s_id_cs.initialized)
		return;
	bb_critical_section_lock(&s_id_cs);
	if(!*pathId) {
		*pathId = bb_resolve_id(path, &s_bb_pathIds, 0, line, kBBPacketType_FileId, ~0U, false);
	}
	bb_critical_section_unlock(&s_id_cs);
}

static bb_color_t bb_resolve_color_str(const char *str)
{
	// clang-format off
	if(!strncmp("0000", str, 4)) return kBBColor_UE4_Black;
	if(!strncmp("1000", str, 4)) return kBBColor_UE4_DarkRed;
	if(!strncmp("0100", str, 4)) return kBBColor_UE4_DarkGreen;
	if(!strncmp("0010", str, 4)) return kBBColor_UE4_DarkBlue;
	if(!strncmp("1100", str, 4)) return kBBColor_UE4_DarkYellow;
	if(!strncmp("0110", str, 4)) return kBBColor_UE4_DarkCyan;
	if(!strncmp("1010", str, 4)) return kBBColor_UE4_DarkPurple;
	if(!strncmp("1110", str, 4)) return kBBColor_UE4_DarkWhite;
	if(!strncmp("1001", str, 4)) return kBBColor_UE4_Red;
	if(!strncmp("0101", str, 4)) return kBBColor_UE4_Green;
	if(!strncmp("0011", str, 4)) return kBBColor_UE4_Blue;
	if(!strncmp("1101", str, 4)) return kBBColor_UE4_Yellow;
	if(!strncmp("0111", str, 4)) return kBBColor_UE4_Cyan;
	if(!strncmp("1011", str, 4)) return kBBColor_UE4_Purple;
	if(!strncmp("1111", str, 4)) return kBBColor_UE4_White;
	// clang-format on
	return kBBColor_Default;
}

static void bb_resolve_and_set_colors(const char *str)
{
	bb_color_t bgColor = kBBColor_Default;
	bb_color_t fgColor = kBBColor_Default;
	size_t len = strlen(str);
	if(len >= 8) {
		fgColor = bb_resolve_color_str(str);
		bgColor = bb_resolve_color_str(str + 4);
	} else if(len >= 4) {
		fgColor = bb_resolve_color_str(str);
	}
	bb_set_color(fgColor, bgColor);
}

static void bb_trace_send(bb_decoded_packet_t *decoded, size_t textlen)
{
	if(textlen >= kBBSize_LogText) {
		char *text = decoded->packet.logText.text;
		size_t preTextSize = text - (char *)decoded;
		while(textlen >= kBBSize_LogText) {
			bb_decoded_packet_t partial;
			memcpy(&partial, decoded, preTextSize);
			bb_strncpy(partial.packet.logText.text, text, kBBSize_LogText);
			partial.type = kBBPacketType_LogTextPartial;
			bb_send(&partial);
			text += kBBSize_LogText - 1;
			textlen -= kBBSize_LogText - 1;
		}

		bb_decoded_packet_t remainder;
		memcpy(&remainder, decoded, preTextSize);
		bb_strncpy(remainder.packet.logText.text, text, textlen + 1);
		bb_send(&remainder);
	} else {
		bb_send(decoded);
	}
}

typedef struct bb_trace_builder_s {
	bb_decoded_packet_t *decoded;
	size_t textOffset;
	size_t textBufferSize;
	char *textStart;
} bb_trace_builder_t;

static b32 bb_trace_begin(bb_trace_builder_t *builder, uint32_t pathId, uint32_t line)
{
	if(!s_bb_trace_packet_buffer) {
		s_bb_trace_packet_buffer = (bbtraceBuffer_t *)malloc(sizeof(*s_bb_trace_packet_buffer));
		if(!s_bb_trace_packet_buffer) {
			return false;
		}
	}
	builder->decoded = (bb_decoded_packet_t *)s_bb_trace_packet_buffer->packetBuffer;
	builder->textOffset = builder->decoded->packet.logText.text - (char *)builder->decoded;
	builder->textBufferSize = sizeof(s_bb_trace_packet_buffer->packetBuffer) - builder->textOffset;
	builder->textStart = s_bb_trace_packet_buffer->packetBuffer + sizeof(s_bb_trace_packet_buffer->packetBuffer) - builder->textBufferSize;
	bb_trace_partial_end();
	bb_fill_header(builder->decoded, kBBPacketType_LogText, pathId, line);
	return true;
}

static void bb_trace_end(bb_trace_builder_t *builder, int len, uint32_t categoryId, bb_log_level_e level, u32 pieInstance)
{
	int maxLen = (int)builder->textBufferSize - 2;
	len = (len < 0 || len > maxLen) ? maxLen : len;
	if(len == 0 || builder->textStart[len - 1] != '\n') {
		builder->textStart[len++] = '\n';
	}
	builder->textStart[len] = '\0';
	if(level == kBBLogLevel_SetColor) {
		bb_resolve_and_set_colors(builder->decoded->packet.logText.text);
	} else {
		builder->decoded->packet.logText.categoryId = categoryId;
		builder->decoded->packet.logText.level = level;
		builder->decoded->packet.logText.pieInstance = pieInstance;
		builder->decoded->packet.logText.colors = s_bb_colors;
		bb_trace_send(builder->decoded, (size_t)len);
	}
}

static void bb_trace_va(uint32_t pathId, uint32_t line, uint32_t categoryId, bb_log_level_e level, u32 pieInstance, const char *fmt, va_list args)
{
	bb_trace_builder_t builder = { BB_EMPTY_INITIALIZER };
	if(!bb_trace_begin(&builder, pathId, line)) {
		return;
	}
	int len = vsnprintf(builder.textStart, builder.textBufferSize, fmt, args);
	bb_trace_end(&builder, len, categoryId, level, pieInstance);
}

void bb_trace(uint32_t pathId, uint32_t line, uint32_t categoryId, bb_log_level_e level, u32 pieInstance, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bb_trace_va(pathId, line, categoryId, level, pieInstance, fmt, args);
	va_end(args);
}

#if BB_COMPILE_WIDECHAR
typedef struct bb_trace_builder_w_s {
	bb_decoded_packet_t *decoded;
	size_t textBufferSize;
	size_t wstrSize;
	bb_wchar_t *wstr;
} bb_trace_builder_w_t;

static b32 bb_trace_begin_w(bb_trace_builder_w_t *builder, uint32_t pathId, uint32_t line)
{
	if(!s_bb_trace_packet_buffer) {
		s_bb_trace_packet_buffer = (bbtraceBuffer_t *)malloc(sizeof(*s_bb_trace_packet_buffer));
		if(!s_bb_trace_packet_buffer) {
			return false;
		}
	}
	builder->decoded = (bb_decoded_packet_t *)s_bb_trace_packet_buffer->packetBuffer;
	builder->textBufferSize = sizeof(s_bb_trace_packet_buffer->packetBuffer) - sizeof(bb_decoded_packet_t) + kBBSize_LogText;
	builder->wstr = s_bb_trace_packet_buffer->wideBuffer;
	builder->wstrSize = BB_ARRAYSIZE(s_bb_trace_packet_buffer->wideBuffer);
	bb_trace_partial_end();
	bb_fill_header(builder->decoded, kBBPacketType_LogText, pathId, line);
	return true;
}

static void bb_trace_end_w(bb_trace_builder_w_t *builder, int len, uint32_t categoryId, bb_log_level_e level, u32 pieInstance)
{
	int maxLen = (int)builder->wstrSize - 2;
	len = (len < 0 || len > maxLen) ? maxLen : len;
	if(builder->wstr[len - 1] != L'\n') {
		builder->wstr[len++] = L'\n';
	}
	builder->wstr[len] = L'\0';
	size_t numCharsConverted = 0;
	bb_wcstombcs_inline(builder->wstr, builder->decoded->packet.logText.text, builder->textBufferSize, &numCharsConverted);
	if(level == kBBLogLevel_SetColor) {
		bb_resolve_and_set_colors(builder->decoded->packet.logText.text);
	} else {
		builder->decoded->packet.logText.categoryId = categoryId;
		builder->decoded->packet.logText.level = level;
		builder->decoded->packet.logText.pieInstance = pieInstance;
		builder->decoded->packet.logText.colors = s_bb_colors;
		bb_trace_send(builder->decoded, numCharsConverted);
	}
}

void bb_trace_va_w(uint32_t pathId, uint32_t line, uint32_t categoryId, bb_log_level_e level, u32 pieInstance, const bb_wchar_t *fmt, va_list args)
{
	bb_trace_builder_w_t builder = { BB_EMPTY_INITIALIZER };
	if(!bb_trace_begin_w(&builder, pathId, line)) {
		return;
	}
#if defined(BB_WIDE_CHAR16) && BB_WIDE_CHAR16
	int len = bb_vswprintf(builder.wstr, builder.wstrSize, fmt, args);
#else
	int len = vswprintf(builder.wstr, builder.wstrSize, fmt, args);
#endif
	bb_trace_end_w(&builder, len, categoryId, level, pieInstance);
}
#endif // #if BB_COMPILE_WIDECHAR

#if BB_COMPILE_WIDECHAR
void bb_trace_w(uint32_t pathId, uint32_t line, uint32_t categoryId, bb_log_level_e level, u32 pieInstance, const bb_wchar_t *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bb_trace_va_w(pathId, line, categoryId, level, pieInstance, fmt, args);
	va_end(args);
}
#endif // #if BB_COMPILE_WIDECHAR

void bb_trace_dynamic(const char *path, uint32_t line, const char *category, bb_log_level_e level, u32 pieInstance, const char *fmt, ...)
{
	va_list args;
	uint32_t pathId = 0;
	uint32_t categoryId = 0;
	bb_resolve_ids(path, category, &pathId, &categoryId, line);
	va_start(args, fmt);
	bb_trace_va(pathId, line, categoryId, level, pieInstance, fmt, args);
	va_end(args);
}

void bb_trace_dynamic_preformatted(const char *path, uint32_t line, const char *category, bb_log_level_e level, u32 pieInstance, const char *preformatted)
{
	uint32_t pathId = 0;
	uint32_t categoryId = 0;
	bb_resolve_ids(path, category, &pathId, &categoryId, line);

	bb_trace_builder_t builder = { BB_EMPTY_INITIALIZER };
	if(!bb_trace_begin(&builder, pathId, line)) {
		return;
	}
	int len = (int)bb_strncpy(builder.textStart, preformatted, builder.textBufferSize);
	bb_trace_end(&builder, len, categoryId, level, pieInstance);
}

#if BB_COMPILE_WIDECHAR
void bb_trace_dynamic_w(const char *path, uint32_t line, const bb_wchar_t *category, bb_log_level_e level, u32 pieInstance, const bb_wchar_t *fmt, ...)
{
	va_list args;
	uint32_t pathId = 0;
	uint32_t categoryId = 0;
	bb_resolve_ids_w(path, category, &pathId, &categoryId, line);
	va_start(args, fmt);
	bb_trace_va_w(pathId, line, categoryId, level, pieInstance, fmt, args);
	va_end(args);
}
#endif // #if BB_COMPILE_WIDECHAR

#if BB_COMPILE_WIDECHAR
void bb_trace_dynamic_preformatted_w(const char *path, uint32_t line, const bb_wchar_t *category, bb_log_level_e level, u32 pieInstance, const bb_wchar_t *preformatted)
{
#if defined(BB_WIDE_CHAR16) && BB_WIDE_CHAR16
	bb_trace_dynamic_w(path, line, category, level, pieInstance, TEXT("%s"), preformatted);
#else  // #if defined(BB_WIDE_CHAR16) && BB_WIDE_CHAR16
	uint32_t pathId = 0;
	uint32_t categoryId = 0;
	bb_resolve_ids_w(path, category, &pathId, &categoryId, line);

	bb_trace_builder_w_t builder = { BB_EMPTY_INITIALIZER };
	if(!bb_trace_begin_w(&builder, pathId, line)) {
		return;
	}
	int len = (int)bb_wstrncpy(builder.wstr, preformatted, builder.wstrSize);
	bb_trace_end_w(&builder, len, categoryId, level, pieInstance);
#endif // #else // #if defined(BB_WIDE_CHAR16) && BB_WIDE_CHAR16
}
#endif // #if BB_COMPILE_WIDECHAR

typedef struct bb_partial_log_builder_s {
	bb_decoded_packet_t decoded;
	uint32_t pathId;
	uint32_t line;
	int len;
	uint8_t pad[4];
} bb_partial_log_builder_t;
bb_thread_local bb_partial_log_builder_t s_bb_partial;

void bb_trace_partial_end(void)
{
	if(s_bb_partial.len) {
		int len = s_bb_partial.len;
		int maxLen;
		bb_decoded_packet_t *decoded = &s_bb_partial.decoded;
		bb_fill_header(decoded, kBBPacketType_LogText, s_bb_partial.pathId, s_bb_partial.line);
		maxLen = sizeof(decoded->packet.logText.text) - 2;
		len = (len < 0 || len > maxLen) ? maxLen : len;
		if(decoded->packet.logText.text[len - 1] != '\n') {
			decoded->packet.logText.text[len++] = '\n';
		}
		decoded->packet.logText.text[len] = '\0';
		decoded->packet.logText.colors = s_bb_colors;
		bb_send(decoded);
		s_bb_partial.len = 0;
	}
}

void bb_trace_partial(const char *path, uint32_t line, const char *category, bb_log_level_e level, u32 pieInstance, const char *fmt, ...)
{
	int textLen, i;
	va_list args;
	uint32_t pathId = 0;
	uint32_t categoryId = 0;
	char text[kBBSize_LogText];
	bb_decoded_packet_t *decoded = &s_bb_partial.decoded;
	bb_resolve_ids(path, category, &pathId, &categoryId, line);

	if(s_bb_partial.len > 0 &&
	   ((u32)level != decoded->packet.logText.level ||
	    categoryId != decoded->packet.logText.categoryId ||
	    pieInstance != decoded->packet.logText.pieInstance)) {
		bb_trace_partial_end();
	}

	s_bb_partial.pathId = pathId;
	s_bb_partial.line = line;
	decoded->packet.logText.level = level;
	decoded->packet.logText.categoryId = categoryId;
	decoded->packet.logText.pieInstance = pieInstance;

	va_start(args, fmt);
	textLen = vsnprintf(text, sizeof(text), fmt, args);
	va_end(args);
	if(textLen < 0) {
		textLen = sizeof(text) - 1;
	}

	for(i = 0; i < textLen; ++i) {
		char c = text[i];
		if(s_bb_partial.len >= (int)(sizeof(text) - 1)) {
			bb_trace_partial_end();

			// help out vs2017 static analysis - bb_trace_partial_end() does this,
			// but it can't figure that out, so it thinks we could write past the
			// end of decoded->packet.logText.text.
			s_bb_partial.len = 0;
		}
		decoded->packet.logText.text[s_bb_partial.len++] = c;
		if(c == '\n') {
			bb_trace_partial_end();
		}
	}
	decoded->packet.logText.text[s_bb_partial.len] = '\0';
}

#endif // #if BB_ENABLED
