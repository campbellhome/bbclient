// Copyright (c) 2012-2019 Matt Campbell
// MIT license (see License.txt)

#include "bb.h"

#if BB_ENABLED

#include "bbclient/bb_connection.h"
#include "bbclient/bb_log.h"
#include "bbclient/bb_packet.h"
#include "bbclient/bb_socket_errors.h"
#include "bbclient/bb_time.h"
#include <string.h> // for memset

#define BBCON_LOG(...)                        \
	if((con->flags & kBBCon_Blackbox) != 0) { \
		bb_log(__VA_ARGS__);                  \
	} else {                                  \
		BB_LOG_A("bbcon", __VA_ARGS__);       \
	}

#define BBCON_WARNING(...)                    \
	if((con->flags & kBBCon_Blackbox) != 0) { \
		bb_warning(__VA_ARGS__);              \
	} else {                                  \
		BB_WARNING_A("bbcon", __VA_ARGS__);   \
	}

#define BBCON_ERROR(...)                      \
	if((con->flags & kBBCon_Blackbox) != 0) { \
		bb_error(__VA_ARGS__);                \
	} else {                                  \
		BB_ERROR_A("bbcon", __VA_ARGS__);     \
	}

enum {
	kBBCon_SendIntervalMillis = 500,
};

void bbcon_init(bb_connection_t *con)
{
	bb_critical_section_init(&con->cs);
	con->socket = BB_INVALID_SOCKET;
	con->sendCursor = con->recvCursor = con->decodeCursor = 0;
	con->prevSendTime = 0;
	con->flags = 0;
	con->state = kBBConnection_NotConnected;
	if(!con->connectTimeoutInterval) {
		con->connectTimeoutInterval = 10000;
	}
}

void bbcon_shutdown(bb_connection_t *con)
{
	bbcon_reset(con);
	bb_critical_section_shutdown(&con->cs);
}

void bbcon_reset(bb_connection_t *con)
{
	bbcon_disconnect(con);
	bbcon_init(con);
}

b32 bbcon_connect_client_async(bb_connection_t *con, u32 remoteAddr, u16 remotePort)
{
	char ipport[32];
	b32 bConnected = false;
	bb_socket testSocket;
	struct sockaddr_in sin;
	bbcon_reset(con);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(remotePort);
	BB_S_ADDR_UNION(sin) = htonl(remoteAddr);
	testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(testSocket == BB_INVALID_SOCKET) {
		BBCON_ERROR("bbcon_connect_client failed - could create socket");
		return false;
	}

	bb_format_ipport(ipport, sizeof(ipport), remoteAddr, remotePort);
	BBCON_LOG("BlackBox client trying to connect to %s", ipport);

	bbnet_socket_nodelay(testSocket, true);
	bbnet_socket_nonblocking(testSocket, true);

	int ret;
	BBCON_LOG("BlackBox client trying to async connect...");
	ret = connect(testSocket, (struct sockaddr *)&sin, sizeof(sin));
	if(ret == BB_SOCKET_ERROR) {
		int err = BBNET_ERRNO;
		if(err == BBNET_EWOULDBLOCK || err == BBNET_EINPROGRESS) {
			BBCON_LOG("BlackBox client connecting async");
			con->socket = testSocket;
			con->flags |= kBBCon_Client;
			con->state = kBBConnection_Connecting;
			con->connectTimeoutTime = bb_current_time_ms() + con->connectTimeoutInterval;
			return true;
		} else {
			BBCON_ERROR("BlackBox client async connect failed with errno %d (%s)", err, bbnet_error_to_string(err));
		}
	} else {
		bConnected = true;
	}

	if(!bConnected) {
		BB_CLOSE(testSocket);
		return false;
	}

	BBCON_LOG("BlackBox client connected");

	// We're connected - send an initial packet and flush to ensure the packet is sent
	con->socket = testSocket;
	con->flags |= kBBCon_Client;
	con->state = kBBConnection_Connected;
	//Send( NULL );
	bbcon_flush(con);

	return true;
}

b32 bbcon_tick_connecting(bb_connection_t *con)
{
	BB_TIMEVAL tv = { BB_EMPTY_INITIALIZER };
	tv.tv_usec = 1000; // 1 millisecond

	fd_set set;
	FD_ZERO(&set);
	BB_FD_SET(con->socket, &set);

	//BBCON_LOG("BlackBox client connecting tick");
	int ret = select((int)con->socket + 1, 0, &set, 0, &tv);
	int err = (ret == BB_SOCKET_ERROR) ? BBNET_ERRNO : 0;
	if(err == BBNET_EWOULDBLOCK) {
		err = 0;
	}
	if(ret == 1) {
		BBCON_LOG("BlackBox client connected");
		con->state = kBBConnection_Connected;
		bbcon_flush(con);
		return true;
	} else if(err) {
		BBCON_ERROR("bbcon_tick_connecting failed with errno %d (%s)", err, bbnet_error_to_string(err));
		bbcon_disconnect(con);
		return false;
	} else {
		u64 now = bb_current_time_ms();
		if(now >= con->connectTimeoutTime) {
			BBCON_ERROR("bbcon_tick_connecting failed - timed out waiting to connect");
			bbcon_disconnect(con);
		}
		return false;
	}
}

b32 bbcon_connect_client(bb_connection_t *con, u32 remoteAddr, u16 remotePort, u32 retries)
{
	char ipport[32];
	b32 bConnected = false;
	bb_socket testSocket;
	struct sockaddr_in sin;
	bbcon_reset(con);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(remotePort);
	BB_S_ADDR_UNION(sin) = htonl(remoteAddr);
	testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(testSocket == BB_INVALID_SOCKET) {
		BBCON_ERROR("bbcon_connect_client failed - could create socket");
		return false;
	}

	bb_format_ipport(ipport, sizeof(ipport), remoteAddr, remotePort);
	BBCON_LOG("BlackBox client trying to connect to %s", ipport);

	for(u32 i = 0; i < retries; ++i) {
		int ret;
		BBCON_LOG("BlackBox client trying to connect (attempt %u)...", i);
		ret = connect(testSocket, (struct sockaddr *)&sin, sizeof(sin));
		if(ret == BB_SOCKET_ERROR) {
			int err = BBNET_ERRNO;
			BBCON_ERROR("BlackBox client connect failed with errno %d (%s)", err, bbnet_error_to_string(err));
		} else {
			bConnected = true;
			break;
		}
	}

	if(!bConnected) {
		BB_CLOSE(testSocket);
		return false;
	}

	BBCON_LOG("BlackBox client connected");

	bbnet_socket_nodelay(testSocket, true);
	bbnet_socket_nonblocking(testSocket, true);

	// We're connected - send an initial packet and flush to ensure the packet is sent
	con->socket = testSocket;
	con->flags |= kBBCon_Client;
	con->state = kBBConnection_Connected;
	//Send( NULL );
	bbcon_flush(con);

	return true;
}

bb_socket bbcon_init_server(u32 *localIp, u16 *localPort)
{
	int ret;
	struct sockaddr_in sin;
	socklen_t sinSize = sizeof(sin);
	bb_socket testSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(testSocket == BB_INVALID_SOCKET) {
		BB_ERROR_A("bbcon", "bbcon_init_server failed - could create socket");
		return BB_INVALID_SOCKET;
	}

	// Bind the socket to any available address on any available port
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	BB_S_ADDR_UNION(sin) = htonl(*localIp);
	sin.sin_port = htons(*localPort);

	ret = bind(testSocket, (struct sockaddr *)&sin, sizeof(sin));
	if(ret == BB_SOCKET_ERROR) {
		BB_ERROR_A("bbcon", "bbcon_init_server failed - could not bind port %d", localPort);
		bbnet_gracefulclose(&testSocket);
		return BB_INVALID_SOCKET;
	}

	ret = getsockname(testSocket, (struct sockaddr *)&sin, &sinSize);
	if(ret == BB_SOCKET_ERROR) {
		BB_ERROR_A("bbcon", "bbcon_init_server failed - could not determine port");
		bbnet_gracefulclose(&testSocket);
		return BB_INVALID_SOCKET;
	}

	*localIp = ntohl(BB_S_ADDR_UNION(sin));
	*localPort = ntohs(sin.sin_port);
	return testSocket;
}

b32 bbcon_connect_server(bb_connection_t *con, bb_socket testSocket, u32 localAddr, u16 localPort)
{
	int ret;
	char ipport[32];
	bb_format_ipport(ipport, sizeof(ipport), localAddr, localPort);
	BBCON_LOG("bbcon_connect_server %p listening on %s", con, ipport);
	ret = listen(testSocket, 10);
	if(ret == BB_SOCKET_ERROR) {
		BBCON_ERROR("bbcon_connect_server failed - could not listen");
		bbnet_gracefulclose(&testSocket);
		return false;
	}

	bbnet_socket_nodelay(testSocket, true); // #investigate: this wasn't set before
	bbnet_socket_nonblocking(testSocket, true);
	con->socket = testSocket;
	con->state = kBBConnection_Listening;
	con->connectTimeoutTime = bb_current_time_ms() + con->connectTimeoutInterval;

	return true;
}

b32 bbcon_tick_listening(bb_connection_t *con)
{
	BB_TIMEVAL tv;
	fd_set set;
	struct sockaddr_in remoteAddrStorage; // client address
	socklen_t addrLen = sizeof(remoteAddrStorage);
	bb_socket clientSock;

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	FD_ZERO(&set);
	BB_FD_SET(con->socket, &set);

	// Now wait for the client to connect
	if(1 != select((int)con->socket + 1, &set, 0, 0, &tv)) {
		u64 now = bb_current_time_ms();
		if(now >= con->connectTimeoutTime) {
			BBCON_ERROR("bbcon_connect_server failed - timed out waiting for client to connect");
			bbcon_disconnect(con);
		}
		return false;
	}

	clientSock = accept(con->socket, (struct sockaddr *)&remoteAddrStorage, &addrLen);
	if(clientSock == BB_INVALID_SOCKET) {
		BBCON_ERROR("bbcon_connect_server failed - client failed to connect");
		bbcon_disconnect(con);
		return false;
	}

	bbnet_socket_nodelay(clientSock, true);
	bbnet_socket_nonblocking(clientSock, true); // #investigate: this wasn't set before

	// We're connected!
	BBCON_LOG("bbcon_connect_server success");
	bb_socket socketToClose = con->socket;
	con->state = kBBConnection_Connected;
	con->socket = clientSock;
	con->flags |= kBBCon_Server;
	bbnet_gracefulclose(&socketToClose);

	return true;
}

b32 bbcon_is_connecting(const bb_connection_t *con)
{
	return con->socket != BB_INVALID_SOCKET && con->state == kBBConnection_Connecting;
}

b32 bbcon_is_listening(const bb_connection_t *con)
{
	return con->socket != BB_INVALID_SOCKET && con->state == kBBConnection_Listening;
}

b32 bbcon_is_connected(const bb_connection_t *con)
{
	return con->socket != BB_INVALID_SOCKET && con->state != kBBConnection_Listening && con->state != kBBConnection_Connecting;
}

void bbcon_disconnect(bb_connection_t *con)
{
	if(con->socket != BB_INVALID_SOCKET) {
		bbnet_gracefulclose(&con->socket);
		con->state = kBBConnection_NotConnected;
	}
}

// Retry sends until we've sent everything or disconnected
static void bbcon_flush_no_lock(bb_connection_t *con, b32 retry)
{
	int ret;
	u32 nSendCursor = 0;
	fd_set set;
	struct timeval tv;

	u64 start = bb_current_time_ms();
	u64 timeout = start + 2000;

	while(nSendCursor < con->sendCursor) {
		FD_ZERO(&set);
		BB_FD_SET(con->socket, &set);

		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		ret = select((int)con->socket + 1, 0, &set, 0, &tv);
		//BBCON_LOG( "Flush select ret:%d", ret );

		if(ret == BB_SOCKET_ERROR) {
			int err = BBNET_ERRNO;
			BBCON_LOG("bbcon_flush: disconnected during select with errno %d (%s)", err, bbnet_error_to_string(err));
			bbcon_disconnect(con);
			break;
		}

		if(ret == 0) {
			u64 now = bb_current_time_ms();
			if(now >= timeout) // OS internal buffer has been full for a really long time (server crashed?), so we're done
			{
				BBCON_LOG("bbcon_flush: timed out after %" PRIu64 " ms", now - start);
				bbcon_disconnect(con);
				break;
			}

			continue; // OS internal buffer is full temporarily, so we'll retry
		}

		ret = send(con->socket, (const char *)(con->sendBuffer + nSendCursor), (int)(con->sendCursor - nSendCursor), 0);
		if(ret == BB_SOCKET_ERROR) {
			int err = BBNET_ERRNO;
			BBCON_LOG("bbcon_flush: disconnected during send with errno %d (%s)", err, bbnet_error_to_string(err));
			bbcon_disconnect(con);
			break;
		}

		nSendCursor += ret;
		if(!retry) {
			break;
		}
	}

	if(nSendCursor < con->sendCursor) {
		if(nSendCursor) {
			memmove(con->sendBuffer, con->sendBuffer + nSendCursor, con->sendCursor - nSendCursor);
			con->sendCursor -= nSendCursor;
		}
	} else {
		con->sendCursor = 0;
	}

	con->prevSendTime = bb_current_time_ms();

	if(con->prevSendTime - start > 10) {
		BBCON_WARNING("bb_flush took %" PRIu64 " ms", con->prevSendTime - start);
	}
}

void bbcon_flush(bb_connection_t *con)
{
	if(!con->cs.initialized)
		return;
	bb_critical_section_lock(&con->cs);
	bbcon_flush_no_lock(con, true);
	bb_critical_section_unlock(&con->cs);
}

void bbcon_try_flush(bb_connection_t *con)
{
	if(!con->cs.initialized)
		return;
	bb_critical_section_lock(&con->cs);
	bbcon_flush_no_lock(con, false);
	bb_critical_section_unlock(&con->cs);
}

static void _bbcon_send(bb_connection_t *con, const void *pData, u16 nBytes)
{
	u64 now;
	u32 nRemaining = nBytes;
	const s8 *pBytes = (const s8 *)(pData);

	u32 kSendBufferSize = sizeof(con->sendBuffer);
	while(nRemaining && con->socket != BB_INVALID_SOCKET) {
		const u32 nBytesToCopy = BB_MIN(kSendBufferSize - con->sendCursor, nRemaining);
		memcpy(con->sendBuffer + con->sendCursor, pBytes, nBytesToCopy);
		con->sendCursor += nBytesToCopy;
		pBytes += nBytesToCopy;
		nRemaining -= nBytesToCopy;

		if(con->sendCursor == kSendBufferSize && nRemaining > 0) {
			bbcon_flush_no_lock(con, true);
		}
	}

	now = bb_current_time_ms();
	if(now > con->prevSendTime + kBBCon_SendIntervalMillis) {
		bbcon_flush_no_lock(con, false);
	}
}

void bbcon_send_raw(bb_connection_t *con, const void *pData, u16 nBytes)
{
	if(!con->cs.initialized)
		return;

	bb_critical_section_lock(&con->cs);

	if(con->socket != BB_INVALID_SOCKET) {
		_bbcon_send(con, pData, nBytes);
	}

	bb_critical_section_unlock(&con->cs);
}

void bbcon_send(bb_connection_t *con, bb_decoded_packet_t *decoded)
{
	u8 buf[BB_MAX_PACKET_BUFFER_SIZE];
	u16 serializedLen;
	if(!con->cs.initialized)
		return;

	serializedLen = bbpacket_serialize(decoded, buf + 2, sizeof(buf) - 2);
	if(!serializedLen) {
		BBCON_ERROR("bbcon_send failed to encode packet");
		return;
	}
	serializedLen += 2;
	buf[0] = (u8)(serializedLen >> 8);
	buf[1] = (u8)(serializedLen & 0xFF);

	//BBCON_LOG( "bbcon_send packetType:%d nBytes:%d m_nSendCursor:%d", decoded->type, serializedLen, con->sendCursor );

	bb_critical_section_lock(&con->cs);

	if(con->socket != BB_INVALID_SOCKET) {
		_bbcon_send(con, buf, serializedLen);
	}

	bb_critical_section_unlock(&con->cs);
}

b32 bbcon_try_send(bb_connection_t *con, bb_decoded_packet_t *decoded)
{
	u8 buf[BB_MAX_PACKET_BUFFER_SIZE];
	u16 serializedLen;
	b32 ret = true;
	if(!con->cs.initialized)
		return ret;

	serializedLen = bbpacket_serialize(decoded, buf + 2, sizeof(buf) - 2);
	if(!serializedLen) {
		BBCON_ERROR("bbcon_send failed to encode packet");
		return ret;
	}
	serializedLen += 2;
	buf[0] = (u8)(serializedLen >> 8);
	buf[1] = (u8)(serializedLen & 0xFF);

	//BBCON_LOG( "bbcon_try_send packetType:%d nBytes:%d m_nSendCursor:%d", decoded->type, serializedLen, con->sendCursor );

	bb_critical_section_lock(&con->cs);

	if(con->socket != BB_INVALID_SOCKET) {
		u32 kSendBufferSize = sizeof(con->sendBuffer);
		const u32 nBytesToCopy = BB_MIN(kSendBufferSize - con->sendCursor, serializedLen);
		if(nBytesToCopy == serializedLen) {
			const s8 *pBytes = (const s8 *)(buf);
			memcpy(con->sendBuffer + con->sendCursor, pBytes, nBytesToCopy);
			con->sendCursor += nBytesToCopy;
		} else {
			ret = false;
		}
	}

	bb_critical_section_unlock(&con->cs);
	return ret;
}

static void bbcon_receive(bb_connection_t *con)
{
	int ret;
	fd_set set;
	b32 isServer;
	struct timeval tv;

	if(con->socket == BB_INVALID_SOCKET)
		return;

	FD_ZERO(&set);
	BB_FD_SET(con->socket, &set);

	isServer = (con->flags & kBBCon_Server) != 0;
	tv.tv_sec = 0;
	tv.tv_usec = (isServer) ? 100 : 0;

	ret = select((int)con->socket + 1, &set, 0, 0, &tv);
	if(ret != 1) {
		if(ret == BB_SOCKET_ERROR) {
			int err = BBNET_ERRNO;
			BBCON_ERROR("bbcon_receive: disconnected during select with errno %d (%s)", err, bbnet_error_to_string(err));
			bbcon_disconnect(con);
		}
		//BBCON_LOG( "select returned %d", ret );
		return;
	} else {
		u32 kRecvBufferSize = sizeof(con->recvBuffer);
		u32 nBytesAvailable = kRecvBufferSize - con->recvCursor;
		int nBytesReceived = recv(con->socket, (char *)(con->recvBuffer + con->recvCursor), (int)nBytesAvailable, 0);
		if(nBytesReceived <= 0) {
			if(nBytesAvailable > 0) {
				int err = BBNET_ERRNO;
				BBCON_ERROR("bbcon_receive: disconnected during recv with errno %d (%s)", err, bbnet_error_to_string(err));
				bbcon_disconnect(con);
			}
			return;
		}

		con->recvCursor += nBytesReceived;

		//BBCON_LOG( "bbcon_receive nBytesReceived:%d decodeCursor:%d recvCursor:%d", nBytesReceived, con->decodeCursor, con->recvCursor );
	}
}

b32 bbcon_decodePacket(bb_connection_t *con, bb_decoded_packet_t *decoded)
{
	const u32 kRecvBufferSize = sizeof(con->recvBuffer);
	const u32 kHalfRecvBufferBytes = kRecvBufferSize / 2;
	b32 valid = false;

	if(!con->cs.initialized)
		return false;

	// #investigate why original impl didn't lock here
	bb_critical_section_lock(&con->cs);

	if(con->socket != BB_INVALID_SOCKET) {
		u16 nDecodableBytes = (u16)(con->recvCursor - con->decodeCursor);
		if(nDecodableBytes >= 3) {
			u8 *cursor = con->recvBuffer + con->decodeCursor;
			u16 nPacketBytes = (u16)((*cursor << 8) + (*(cursor + 1)));
			if(nDecodableBytes >= nPacketBytes) {
				//BBCON_LOG( "bbcon_decodePacket PRE decodeCursor:%d recvCursor:%d nPacketBytes:%d", con->decodeCursor, con->recvCursor, nPacketBytes );

				u8 *buffer = con->recvBuffer + con->decodeCursor;
				valid = bbpacket_deserialize(buffer + 2, nPacketBytes - 2U, decoded);

				con->decodeCursor += nPacketBytes;

				//BBCON_LOG( "bbcon_decodePacket POST decodeCursor:%d recvCursor:%d valid:%d", con->decodeCursor, con->recvCursor, valid );

				// TODO: rather lame to keep resetting the buffer - this should be a circular buffer
				if(con->decodeCursor >= kHalfRecvBufferBytes) {
					u16 nBytesRemaining = (u16)(con->recvCursor - con->decodeCursor);
					//BBCON_LOG( "bbcon_decodePacketReset PRE decodeCursor:%d recvCursor:%d", con->decodeCursor, con->recvCursor );
					memmove(con->recvBuffer, con->recvBuffer + con->decodeCursor, nBytesRemaining);
					con->decodeCursor = 0;
					con->recvCursor = nBytesRemaining;
					//BBCON_LOG( "bbcon_decodePacketReset POST decodeCursor:%d recvCursor:%d", con->decodeCursor, con->recvCursor );
				}
			}
		}
	}

	bb_critical_section_unlock(&con->cs);

	return valid;
}

void bbcon_tick(bb_connection_t *con)
{
	if(con->socket != BB_INVALID_SOCKET && con->cs.initialized) {
		u64 now = bb_current_time_ms();
		if(now > con->prevSendTime + kBBCon_SendIntervalMillis) {
			bbcon_try_flush(con);
		}

		// #investigate why original impl didn't lock here
		bb_critical_section_lock(&con->cs);

		bbcon_receive(con);

		bb_critical_section_unlock(&con->cs);
	}
}

#endif // #if BB_ENABLED
