// IPPerfTest.h : Include file for standard system include files,
// or project specific include files.

#ifndef _IPPERFTEST_H_
#define _IPPERFTEST_H_

#pragma once

//#include <iostream>

/* includes */
#ifdef _WIN32
#define IM_LITTLE_ENDIAN	1
/*
* Include windows.h without Windows Sockets 1.1 to prevent conflicts with
* Windows Sockets 2.0.
*/
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

//WIN32 Interop
#include "./Win32_Interop/Win32_Portability.h"
#include "./Win32_Interop/win32_types.h"
#include "./Win32_Interop/Win32_PThread.h"
#include "./Win32_Interop/Win32_ThreadControl.h"

#include <winsock2.h>
#include <MSWsock.h>
#include <ws2tcpip.h>
#include <Windows.h>
#endif  /* _WIN32 */

#include <stdio.h>
#include <stdlib.h> 
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <limits.h>
POSIX_ONLY(#include <unistd.h>)
#include <errno.h>
POSIX_ONLY(#include <inttypes.h>)
POSIX_ONLY(#include <pthread.h>)
POSIX_ONLY(#include <syslog.h>)
POSIX_ONLY(#include <netinet/in.h>)
#include <signal.h>

#include <ctype.h>
POSIX_ONLY(#include <fcntl.h>)
POSIX_ONLY(#include <sys/ioctl.h>)
POSIX_ONLY(#include <sys/socket.h>)
POSIX_ONLY(#include <sys/un.h>)
POSIX_ONLY(#include <arpa/inet.h>)
POSIX_ONLY(#include <sys/types.h>)
POSIX_ONLY(#include <sys/wait.h>)
POSIX_ONLY(#include <sys/stat.h>)
POSIX_ONLY(#include <sys/select.h>)
POSIX_ONLY(#include <sys/resource.h>)
POSIX_ONLY(#include <search.h>)

POSIX_ONLY(#include <sys/mman.h>)
#ifndef _WIN32
#include <netdb.h>
#else
#include <Iphlpapi.h>
#include "./Win32_Interop/Win32_APIs.h"
//#include "Win32_Time.h"
#endif
#include "tommyhashlin.h"

/* defines */
#define ARGS_IPPERF "n:dhVNYC:P:L:p:S:s:l:w:T:t:"
#define PKT_SIZE		1400
#define ETH_ADDR_LEN    	6               /* Octets in one ethernet addr   */
#define ETHER_HDRLEN    	14
#define ETHERMTU		1500
#define ETHER_JUMBO_MTU		9000
#define IEEE8021Q_TAGLEN	4
#define IEEE8021AH_LEN		10
#define PPP_TAGLEN              2
#define MAX_MCAST_GROUPS	20
#define ROUTING_SEGMENT_MAX	16
#if defined ENABLE_PLABEL
#define PREFIX_LABEL_LEN	16
#define AF_PLABEL		255
#endif

#define SRVBUFLEN (256+32)
#define CFG_LINE_LEN(x) (SRVBUFLEN-strlen(x))
#define THREADS_PER_CPU	1

#define MANTAINER "Erwin Herzog <e.herzog76@live.de>"
#define USAGE_HEADER "THB-IPPerf, IPPerf 1.0.0.0"
#define BUILD_DATE	"20190814"
#define COMPILE_ARGS ""

#ifndef HAVE_UID_GID
typedef int uid_t;
typedef int gid_t;
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef FALSE_NONZERO
#define FALSE_NONZERO 2
#endif
#ifndef ERR
#define ERR -1
#endif
#ifndef SUCCESS
#define SUCCESS 0
#endif

#define	E_NOTFOUND	2

typedef enum COMPLETION_KEY
{
	CK_STOP,
	CK_START,
	CK_CONTINUE
};
typedef enum _OPERATION_MODE
{
	OP_CLIENT,
	OP_CLIENTONLY,
	OP_SERVER,
	OP_SERVERONLY
} OPERATION_MODE;

typedef enum _OPERATION_TYPE
{
	OP_NONE,
	OP_RECV,
	OP_SEND,
	OP_RESEND,
	OP_RECVRESP,
	OP_SENDRECV
} OPERATION_TYPE;

typedef enum _CMD {
	CMD_NONE,
	CMD_EXIT,
	CMD_EXIT_MAINLOOP,
	CMD_WAIT_4_ACK,
	CMD_SEND_ACK,
	CMD_UNKNOWN
} CMD;

typedef enum _PKT_TYPE
{
	PKT_ACK,
	PKT_REACK,
	PKT_DATA,
	PKT_DATARETRANSMIT
} PKT_TYPE;

#ifdef _WIN32
//struct EXTENDED_RIO_BUF : public RIO_BUF
//{
//	OPERATION_TYPE operation;
//};

struct _EXTENDED_RIO_BUF {
	RIO_BUFFERID BufferId;
	ULONG Offset;
	ULONG Length;
	OPERATION_TYPE operation;
};
typedef struct _EXTENDED_RIO_BUF EXTENDED_RIO_BUF;
#endif // _WIN32

struct host_addr {
	u_int8_t family;
	union {
		struct in_addr ipv4;
#if defined ENABLE_IPV6
		struct in6_addr ipv6;
#endif
#if defined ENABLE_PLABEL
		u_char plabel[PREFIX_LABEL_LEN];
#endif
	} address;
};

struct host_mask {
	u_int8_t family;
	union {
		u_int32_t m4;
#if defined ENABLE_IPV6
		u_int32_t m6[4];
#endif
	} mask;
};

typedef struct {
	char *val;
	u_int16_t len;
} pm_hash_key_t;

typedef struct {
	pm_hash_key_t key;
	u_int16_t off;
} pm_hash_serial_t;

typedef struct {
	char PktType;
	u_int32_t ThrNr;
	u_int64_t PktNr;
	u_int64_t PktLength;
	void *PktData;
} PKT_HEADER;

struct ClientNode {
#if defined ENABLE_IPV6
	struct sockaddr_in6 client;
#else
	struct sockaddr_in client;
#endif
	//struct host_addr ip;				  /* Client-IP */
	//u_int16_t port;
	u_int64_t pktCounter;
	u_int64_t errCounter;
	u_int64_t lastActPkt;
	u_int64_t PktNr;
	tommy_node node;
};

#include "getopt.h"
#include "util.h"


#if (!defined __IPPERFTEST_C)
#define EXT extern
#else
#define EXT
#endif
EXT void usage_daemon(char *);
EXT void version_daemon(char *);
EXT int tommy_hash_cmpClientNode(const void* , const void*);
EXT void tommy_print_ClientNodeStatistics(const void*);
EXT void* WorkerThread(void*);
#ifdef _WIN32
EXT char *AllocateBufferSpace(const unsigned long, const unsigned long, unsigned long*, unsigned long*);
EXT BOOL WINAPI HandlerRoutine(_In_ DWORD);
#else
EXT void HandlerRoutine(int);
#endif // _WIN32
EXT void endprog(int);
#undef EXT


/* global Variables */
#if (!defined __IPPERFTEST_C)
#define EXT extern
#else
#define EXT
#endif
EXT volatile u_int32_t bRunning;
EXT pthread_mutex_t mutex_mainloop;
EXT pthread_cond_t  cond_mainloop;
EXT char listener_ip[SRVBUFLEN];
EXT u_int32_t listener_port;
EXT char dst_ip[SRVBUFLEN];
EXT u_int32_t dst_port;
EXT u_int32_t PktCount;
EXT u_int32_t PktSize;
EXT BOOL debug;
EXT u_int32_t PROTO;
EXT u_int64_t WndSize;
EXT u_int32_t recvTimeout;
EXT OPERATION_MODE OPMode;
#ifdef _WIN32
SOCKET MainSock;
EXT int bNotify;
EXT int bSndChkResult;
EXT ULONG netSend(RIO_EXTENSION_FUNCTION_TABLE *, RIORESULT *, HANDLE, RIO_CQ, RIO_RQ, PRIO_BUF, PRIO_BUF, PRIO_BUF, BOOL);
#else
int MainSock;
#endif // _WIN32
#undef EXT

#endif /* _IPPERFTEST_H_ */
