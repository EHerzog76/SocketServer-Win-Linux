/* defines */
#define __IPPERFTEST_C

#pragma comment(lib, "ws2_32.lib")

/* includes */
#include "IPPerfTest.h"

#ifdef _WIN32
static const DWORD RIO_PENDING_RECVS = 10;
static const DWORD RIO_PENDING_SENDS = 10;
static const DWORD ADDR_BUFFER_SIZE = 64;
static const DWORD RIO_MAX_RESULTS = 10;

static const DWORD RECV_BUFFER_SIZE = 9000;
static const DWORD SEND_BUFFER_SIZE = 9000;

#define THREAD_EXIT		0xFFFFFFFE
#endif // _WIN32

typedef struct
{
	HANDLE hThread;
	u_int32_t ThreadNr;
#ifdef _WIN32
	HANDLE hIOCP;
	HANDLE hIOCPSend;
#endif
	u_int64_t RecvCounter;
	u_int64_t SendCounter;
	u_int64_t retransmitCounter;
	u_int64_t RecvBytes;
	u_int64_t SendBytes;
	u_int64_t minRTT;
	u_int64_t avgRTT;
	u_int64_t maxRTT;
} ThreadParams;

u_int32_t maxThreads = 0;
ThreadParams* pThreadParams = NULL;
char PKTDATA[64];
clock_t startTime, endTime;
time_t startTime1, endTime1;
double runTime;

/*
#ifdef _WIN32
	SYSTEM_INFO	SystemInfo;
	unsigned int	WinCount;
	DWORD		ThreadID;

	//Determine how many processors are on the system.
	GetSystemInfo(&SystemInfo);

	// Create worker threads based on the number of processors available on the system.
	// Create config.threads_per_cpu worker threads for each processor:
	if (config.threads_per_cpu < 1)
		config.threads_per_cpu = 1;

	for (WinCount = 0; WinCount < SystemInfo.dwNumberOfProcessors * config.threads_per_cpu; WinCount++) {
		HANDLE	ThreadHandle;
		//Create a server worker thread and pass the completion port to the thread:
		if ((ThreadHandle = CreateThread(NULL, 0, ServerWorkerThread, CompletionPort, 0, &ThreadID)) == NULL)
		{
			Log(LOG_ERR, "ERROR ( %s/core ): ServerWorkerThread creation failed with error %d. Exiting...\n\n", config.name, GetLastError());
			endprog(1);
		}

		//   Close   the   thread   handle
		CloseHandle(ThreadHandle);
	}
#endif // _WIN32
*/

void usage_daemon(char *prog_name)
{
	printf("%s (%s)\n", USAGE_HEADER, BUILD_DATE);
	printf("Usage: %s [ -d ] [ -P TCP|UDP ] [ -L IP address ] [ -p port ] [ -S Target-Server ] [ -s Target-Serverport ] [ , ... ] ]\n", prog_name);
	printf("       %s [ -h ]\n", prog_name);
	printf("\nGeneral options:\n");
	printf("  -h  \tShow this page.\n");
	printf("  -V  \tShow version and compile-time options and exit.\n");
	printf("  -P  \tUse UDP or TCP as Protocol.\n");
	printf("  -L  \tBind to the specified IP address.\n");
	printf("  -p  \tListen on the specified port.\n");
	printf("  -S  \tOperate in client-Mode and send packets to Server IP.\n");
	printf("  -s  \tRemote-Server-Port.\n");
	printf("  -n  \tSend number of Packets.\n");
	printf("  -l  \tPacketsize in 64Byte steps.\n");
	printf("  -w  \tWindowsize, how many Data-Packet can be sent without an Ack-Packet, 0=disabled.\n");
	printf("  -t  \tReceive-Timeout in msec, default=1000msec.\n");
	printf("  -T  \tNumber of Threads to use. If not specified the number of Threads will be calculated by the number of CPUs.\n");
	printf("  -N  \tenable Receive-Notify RIONotify will be enabled and also Check Sendresults -C.\n");
	printf("  -C  \tCheck and wait for local Sendresults.\n");
	printf("  -d  \tEnable debug\n");
	//printf("  -r  \tRefresh time (in seconds)\n");
	printf("\n");
	printf("  See QUICKSTART or visit http://www.thbweb.eu/ for examples.\n");
	printf("\n");
	printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

void version_daemon(char *header)
{
	printf("%s (%s)\n", header, BUILD_DATE);
	printf("%s\n\n", COMPILE_ARGS);
	printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

int main(int argc, char **argv) {
	u_int32_t i32Result = 0;
	u_int32_t i = 0;
	int errflag = 0, NrCPUs = 0, cp;
	char strTemp[SRVBUFLEN];

	/* set Defaults */
	runTime = 0;
	bNotify = FALSE;
	bSndChkResult = FALSE;
	strlcpy(listener_ip, "0.0.0.0", 256);
	memset(dst_ip, 0, sizeof(dst_ip));
	listener_port = 0;
	dst_port = 3000;
	debug = FALSE;
	PROTO = SOCK_DGRAM;
	PktSize = PKT_SIZE;
	WndSize = 64000;
	recvTimeout = INFINITE;
	PktCount = 0;		//ToDo:  stop after Nr. of PktCount are sent
	for (i = 0; i < 64; i++) {
		PKTDATA[i] = i + 64;
	}
	maxThreads = 0;
	NrCPUs = getCPUs();

	/* getting commandline values */
	while (!errflag && ((cp = getopt(argc, argv, ARGS_IPPERF)) != -1)) {
		switch (cp) {
		case 'L':
			strlcpy(listener_ip, optarg, SRVBUFLEN);
			break;
		case 'p':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			listener_port = atoi(strTemp);
			break;
		case 'd':
			debug = TRUE;
			break;
		case 'P':
			if (strcmp(optarg, "TCP") == 0) {
				PROTO = SOCK_STREAM;
			}
			else {
				PROTO = SOCK_DGRAM;
			}
			break;
		case 'S':
			strlcpy(dst_ip, optarg, SRVBUFLEN);
			break;
		case 's':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			dst_port = atoi(strTemp);
			break;
		case 'n':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			PktCount = atoi(strTemp);
			break;
		case 'l':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			PktSize = atoi(strTemp);
			if (PktSize < 64)
				PktSize = 64;
			PktSize = (PktSize / 64) * 64;
			break;
		case 'T':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			maxThreads = atoi(strTemp);
			break;
		case 't':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			recvTimeout = atoi(strTemp);
			if (recvTimeout == 0)
				recvTimeout = INFINITE;
			break;
		case 'N':
			bNotify = TRUE;
			break;
		case 'C':
			bSndChkResult = TRUE;
			break;
		case 'w':
			strlcpy(strTemp, optarg, SRVBUFLEN);
			WndSize = atoi(strTemp);
			break;
		case 'h':
			usage_daemon(argv[0]);
			exit(0);
			break;
		case 'V':
			version_daemon(USAGE_HEADER);
			exit(0);
			break;
		default:
			usage_daemon(argv[0]);
			exit(1);
			break;
		}
	}

	printf("INFO: Selected configuration:\n");
	if (PROTO == SOCK_STREAM)
		printf("\tProto: TCP\n");
	else
		printf("\tProto: UDP\n");
	if (bNotify) {
		printf("\tRIO-Notify is enalbed.\n");
	}
	else
		printf("RIO-Notify is disabled for Receive.\n");
	if (bSndChkResult)
		printf("\tCheck Sendresults is enabled.\n");
	if (dst_ip[0] == '\0') {
		OPMode = OP_SERVERONLY;
		printf("\tServer-Mode listen on %s:%d\n", listener_ip, listener_port);
	}
	else {
		OPMode = OP_CLIENTONLY;
		printf("\tClient-Mode send packets to Server: %s:%d\n", dst_ip, dst_port);
	}
	if (maxThreads == 0) {
		maxThreads = NrCPUs * THREADS_PER_CPU;
		if (maxThreads == 0)
			maxThreads = 1;
	}
	printf("\tUse %d Threads\n", maxThreads);
	printf("\tWndSize: %d\n", WndSize);
	if(recvTimeout == INFINITE)
		printf("\tRecv-Timeout: NO, no retransmits are possible!\n");
	else
		printf("\tRecv-Timeout: %d\n", recvTimeout);
	if (debug)
		printf("\tDebug-Mode is enabled.\n");

	pthread_mutex_init(&mutex_mainloop, NULL);
	pthread_cond_init(&cond_mainloop, NULL);
	
	pThreadParams = malloc(sizeof(ThreadParams) * maxThreads);
	for (i = 0; i < maxThreads; i++) {
		pThreadParams[i].hThread = NULL;
		pThreadParams[i].ThreadNr = -1;
		pThreadParams[i].RecvCounter = 0;
		pThreadParams[i].SendCounter = 0;
		pThreadParams[i].RecvBytes = 0;
		pThreadParams[i].SendBytes = 0;
	}

#ifdef _WIN32
	MainSock = INVALID_SOCKET;
#else
	MainSock = -1;
#endif

#ifdef _WIN32
	WSADATA	wsaData;
	DWORD		WinRet;

	if ((WinRet = WSAStartup(0x0202, &wsaData)) != 0)
	{
		printf("ERROR: WSAStartup failed with error %d. Exiting...\n\n", WinRet);
		endprog(1);
	}
#endif // _WIN32

	bRunning = 1;
	printf("IPPerfTest...\n");

	for (i = 0; i < maxThreads; i++) {
		i32Result = pthread_create(&(pThreadParams[i].hThread), NULL, WorkerThread, &(pThreadParams[i]));
		if (i32Result != 0) {
			printf("ERROR: Worker-Thread could not be created !\n");
		}
		else
		{
			pThreadParams[i].ThreadNr = i;
		}
	}
	startTime = clock();
	startTime1 = time(NULL);

	//Ctrl-C Handler
#ifdef _WIN32
	SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#else
	struct sigaction SigAct;
	SigAct.sa_handler = HandlerRoutine;
	sigaction(SIGINT, &SigAct, NULL);
#endif // _WIN32

	pthread_mutex_lock(&mutex_mainloop);	// used for waiting of end of program...
	printf("Press CTRL+C to exit...\n");
	while (bRunning) {

		/* Wait for end of program */
		pthread_cond_wait(&cond_mainloop, &mutex_mainloop);
	}
	bRunning = 0;
	endTime = clock();
	endTime1 = time(NULL);
	runTime = ((double)(endTime - startTime)) / CLOCKS_PER_SEC; // in seconds

	endprog(0);
	return(0);
}

#ifdef _WIN32
char *AllocateBufferSpace(const DWORD bufSize, const DWORD bufCount, DWORD *totalBufferSize, DWORD *totalBufferCount)
{
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	const unsigned __int64 granularity = systemInfo.dwAllocationGranularity;
	const unsigned __int64 desiredSize = bufSize * bufCount;
	unsigned __int64 actualSize = (desiredSize / granularity)*granularity;
	actualSize = actualSize + (((desiredSize % granularity) > 0) ? granularity : 0);

	if (actualSize > ULONG_MAX)
	{
		actualSize = (ULONG_MAX / granularity) * granularity;
	}

	*totalBufferCount = actualSize / bufSize;
	if (bufCount < *totalBufferCount)
		*totalBufferCount = bufCount;
	*totalBufferSize = actualSize;
	char *pBuffer = (char*)VirtualAllocEx(GetCurrentProcess(), 0, *totalBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pBuffer == 0)
	{
		printf("ERROR: AllocateBufferSpace-VirtualAllocEx failed (errno: %d).\n", GetLastError());
		exit(0);
	}
	return pBuffer;
}
#endif // _WIN32

int tommy_hash_cmpClientNode(const void* arg, const void* obj)
{
	//Compare IP and Port
	return(sa_addrport_cmp((struct sockaddr *)arg, &((const struct ClientNode*)obj)->client));
}

void tommy_print_ClientNodeStatistics(const void* Node) {
	struct ClientNode *objClient = Node;
	char strIP[256];

	sa_to_str(strIP, objClient->client);
	printf("Client: %s:%d, \tPktCounter: %d, Error-Counter: %d\n", strIP, ntohs(objClient->client.sin_port), objClient->pktCounter, objClient->errCounter);
}

#ifdef _WIN32
ULONG netSend(RIO_EXTENSION_FUNCTION_TABLE *pFNTable, RIORESULT *sendResults, HANDLE hIOCPSend, RIO_CQ CQ_Send, RIO_RQ requestQueue, PRIO_BUF pSendBuffer, PRIO_BUF pLocalAddr, PRIO_BUF pRemoteAddr, BOOL bNotify) {
	INT notifyResult = 0;
	DWORD numberOfBytes = 0, l_Flags = 0;
	ULONG_PTR completionKey = 0;
	OVERLAPPED* pOverlapped = 0;
	ULONG nResults = 0;

	if (bNotify)
		l_Flags = 0;
	else
		l_Flags = RIO_MSG_DONT_NOTIFY;

	if (!pFNTable->RIOSendEx(requestQueue, pSendBuffer, 1, NULL, pRemoteAddr, NULL, NULL, l_Flags, pSendBuffer))
	{
		printf_s("RIOSend Error: %d\n", GetLastError());
		return(THREAD_EXIT);
	}

	if (bNotify) {
		//Notify for Sending-Ready
		notifyResult = pFNTable->RIONotify(CQ_Send);
		if (notifyResult != ERROR_SUCCESS)
		{
			printf_s("RIONotify Error: %d\n", GetLastError());
			return(THREAD_EXIT);
		}

		if (!GetQueuedCompletionStatus(hIOCPSend, &numberOfBytes, &completionKey, &pOverlapped, INFINITE))
		{
			printf_s("GetQueuedCompletionStatus Error: %d\n", GetLastError());
			return(THREAD_EXIT);
		}

		/// exit when CK_STOP
		if (completionKey == (ULONG_PTR)CK_STOP) {
			return(THREAD_EXIT);
		}
	}
	memset(sendResults, 0, sizeof(sendResults));
	if (bNotify) {
		nResults = pFNTable->RIODequeueCompletion(CQ_Send, sendResults, RIO_MAX_RESULTS);
	}
	else {
		if (bSndChkResult) {
			do {
				nResults = pFNTable->RIODequeueCompletion(CQ_Send, sendResults, RIO_MAX_RESULTS);
				/* if (nResults == 0)
					YieldProcessor();
				else
					break;
				*/
			} while (nResults == 0);
		}
		else
			nResults = 1;
	}

	return(nResults);
}
#endif

void* WorkerThread(void* ThreadParam) {
	ThreadParams *ThreadInfo = (ThreadParams*)ThreadParam;
	int rc, yes = 1, no = 0, ExitCode = 0, bRecvTimeOut = 0, bRecvActive = 0;
	unsigned long ret;
	struct host_addr addr;
	char *sndBuffer = NULL;
	char DataSrcKey[256];
	unsigned long i = 0, x = 0, offset = 0;
	OPERATION_TYPE next_OPType = OP_NONE;
	CMD next_CMD = CMD_NONE;
	int PktPrefix = ThreadInfo->ThreadNr;
	u_int32_t minPktLength = sizeof(PKT_HEADER) - sizeof(void*);
	u_int64_t PktNr = 0, AckPktNr = 0, deltaTime = 0; 
	PKT_HEADER pktHeader;
	tommy_hashlin ClientLookup;
	struct ClientNode *objClient = NULL, localClient;
	clock_t recvStart;

	//ToDo:
	//	Thread/CPU-Pinning:
	//auto mask = (static_cast<DWORD_PTR>(1) << core); //core number starts from 0 auto
	//ret = SetThreadAffinityMask(GetCurrentThread(), mask);

#ifdef _WIN32
	SOCKET sock;
#else
	int sock;
#endif // _WIN32

#if defined ENABLE_IPV6
	struct sockaddr_storage server, remoteServer, client, remoteClient;
	struct ipv6_mreq multi_req6;
#else
	struct sockaddr server, remoteServer, client, remoteClient;
#endif
	int clen = sizeof(client), slen;
	struct ip_mreq multi_req4;

	memset(&server, 0, sizeof(server));


#if (defined ENABLE_IPV6)
	if (!listener_ip) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(listener_port);
		slen = sizeof(struct sockaddr_in6);
	}
#else
	if (!listener_ip) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = htonl(0);
		sa4->sin_port = htons(listener_port);
		slen = sizeof(struct sockaddr_in);
	}
#endif
	else {
		trim_spaces(listener_ip);
		ret = str_to_addr(listener_ip, &addr);
		if (!ret) {
			printf("ERROR: 'listener_ip' value is not valid. Exiting.\n");
			endprog(1);
		}
		slen = addr_to_sa((struct sockaddr *)&server, &addr, listener_port);
	}

	if (dst_ip[0] != '\0') {
		trim_spaces(dst_ip);
		ret = str_to_addr(dst_ip, &addr);
		if (!ret) {
			printf("ERROR: 'Destination-IP' value is not valid. Exiting.\n");
			endprog(1);
		}
		slen = addr_to_sa((struct sockaddr *)&remoteServer, &addr, dst_port);
	}

	//socket creation
#ifdef _WIN32
	sock = WSASocket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_REGISTERED_IO); //WSA_FLAG_OVERLAPPED
	if (sock == INVALID_SOCKET) {
#else
	sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
	if (sock < 0) {
#endif // _WIN32

#if (defined ENABLE_IPV6)
		//retry with IPv4
		if (!listener_ip) {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

			sa4->sin_family = AF_INET;
			sa4->sin_addr.s_addr = htonl(0);
			sa4->sin_port = htons(listener_port);
			slen = sizeof(struct sockaddr_in);

#ifdef _WIN32
			sock = WSASocket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_REGISTERED_IO); //WSA_FLAG_OVERLAPPED
#else
			sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
#endif // _WIN32
		}
#endif
	}

#ifdef _WIN32
	if (sock == INVALID_SOCKET) {
#else
	if (sock < 0) {
#endif // _WIN32
		printf("ERROR: socket() in Thread-Nr %d failed.\n", ThreadInfo->ThreadNr);
		pthread_exit(1);
	}

	rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
	// SO_REUSE_UNICASTPORT  for UDP is set by default.
	if (rc < 0) printf("WARN: setsockopt() failed for SO_REUSEADDR.\n");
#ifndef _WIN32
	rc = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, sizeof(yes));
	rc = setsockopt(sock, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF/EBPF, (char *)&yes, sizeof(yes));
	//	or
	//int cpu = 1;
	//setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
#else
	//Set Receivetimeout on Socket
	//if(recvTimeout)
	//	rc = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout, sizeof(recvTimeout));
#endif // !_WIN32

	if (PROTO == SOCK_STREAM) {
		//Turn off nagle
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)opt, sizeof(int));

		//SIO_LOOPBACK_FAST_PATH
	}

	setnonblocking(sock);

	//ToDo:
	//	Thread-Pinning

	//ToDo:
	//	e.g. for Intel   ixgbe:
	//			xps_cpus   Enable
	//	GRO for TCP enabled, for UDP it can be disabled (let it ENABLED !!!)


#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
	rc = setsockopt(sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *)&no, (socklen_t) sizeof(no));
	if (rc < 0) printf("WARN: setsockopt() failed for IPV6_BINDV6ONLY.\n");
#endif

	int l = sizeof(int);
	int saved = 0, obtained = PKT_SIZE;
/*
	getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
	Setsocksize(sock, SOL_SOCKET, SO_RCVBUF, &obtained, l);
	getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

	if (obtained < saved) {
		Setsocksize(sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
		getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
	}
	printf("INFO: Packet-Size: obtained=%d target=%d.\n", obtained, PKT_SIZE);
*/
	rc = bind(sock, (struct sockaddr *) &server, slen);
#ifdef _WIN32
	if (rc == SOCKET_ERROR) {
		printf("ERROR: bind() to ip=%s port=%d/udp failed (errno: %d).\n", listener_ip, listener_port, WSAGetLastError());
#else
	if (rc < 0) {
		printf("ERROR: bind() to ip=%s port=%d/udp failed (errno: %d).\n", listener_ip, listener_port, errno);
#endif // _WIN32
		pthread_exit(1);
	}

	sndBuffer = malloc(PktSize);
	l = PktSize / 64;
	offset = 0;
	for (i = 0; i < l; i++) {
		memcpy_s(sndBuffer + offset, PktSize, PKTDATA, 64);
		offset += 64;
	}

#ifdef _WIN32
	RIO_EXTENSION_FUNCTION_TABLE l_rio;
	RIO_CQ completionQueue_Recv = 0, completionQueue_Send = 0;
	RIO_RQ l_requestQueue = 0;
	HANDLE hIOCPRecv = NULL, hIOCPSend = NULL;
	RIO_BUFFERID l_sendBufferId;
	RIO_BUFFERID l_recvBufferId;
	RIO_BUFFERID l_addrBufferId;
	INT notifyResult = 0;
	DWORD numberOfBytes = 0, l_Flags = 0, lastError = 0;
	ULONG_PTR completionKey = 0;
	OVERLAPPED* pOverlapped = 0;
	OVERLAPPED rcvOverlapped;
	OVERLAPPED_ENTRY rcvOverlappedEntries[64];
	RIORESULT *results, *sendResults;
	ULONG numResults = 0, numSendResults = 0, maxOverlappedEntries = 64, recvOvEntries = 0;
	EXTENDED_RIO_BUF* pBuffer = NULL, *sendBuf = NULL, *pRecvBufs = NULL, *pAddrBufs = NULL;
	char *sendOffset = NULL, *recvOffset = NULL, *addrOffset = NULL, *BufferOffset = NULL;

	char* l_sendBufferPointer = NULL;
	char* l_recvBufferPointer = NULL;
	char* l_addrBufferPointer = NULL;

	/// RIO_BUF for RECV (circular)
	EXTENDED_RIO_BUF* l_recvRioBufs = NULL;
	DWORD l_recvRioBufTotalCount = 0;
	__int64 l_recvRioBufIndex = 0;

	/// RIO_BUF for SEND (circular)
	EXTENDED_RIO_BUF* l_sendRioBufs = NULL;
	DWORD l_sendRioBufTotalCount = 0;
	__int64 l_sendRioBufIndex = 0;

	/// RIO_BUF for ADDR (circular)
	EXTENDED_RIO_BUF* l_addrRioBufs = NULL;
	DWORD l_addrRioBufTotalCount = 0;
	__int64 l_addrRioBufIndex = 0;

	/// RIO function table
	GUID functionTableId = WSAID_MULTIPLE_RIO;
	DWORD dwBytes = 0;

	if (NULL != WSAIoctl(sock, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &functionTableId, sizeof(GUID), (void**)&l_rio, sizeof(l_rio), &dwBytes, NULL, NULL))
	{
		printf_s("ERROR: WSAIoctl Error: %d\n", GetLastError());
		pthread_exit(1);
	}

	//if (bNotify) {
		/// rio's completion manner: iocp
		hIOCPRecv = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
		if (NULL == hIOCPRecv)
		{
			printf_s("CreateIoCompletionPort Error: %d\n", GetLastError());
			pthread_exit(1);
		}
		ThreadInfo->hIOCP = hIOCPRecv;

		OVERLAPPED overlapped;
		RIO_NOTIFICATION_COMPLETION completionType;

		completionType.Type = RIO_IOCP_COMPLETION;
		completionType.Iocp.IocpHandle = hIOCPRecv;
		completionType.Iocp.CompletionKey = (void*)CK_START;
		completionType.Iocp.Overlapped = &overlapped;

		/// creating RIO CQ, which is bigger than (or equal to) RQ size
		completionQueue_Recv = l_rio.RIOCreateCompletionQueue(RIO_PENDING_RECVS, &completionType);
		if (completionQueue_Recv == RIO_INVALID_CQ)
		{
			printf_s("RIOCreateCompletionQueue for Receive Error: %d\n", GetLastError());
			pthread_exit(0);
		}
	//}

	//if (bNotify) {
		hIOCPSend = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
		if (NULL == hIOCPSend)
		{
			printf_s("CreateIoCompletionPort Error: %d\n", GetLastError());
			pthread_exit(1);
		}
		ThreadInfo->hIOCPSend = hIOCPSend;

		OVERLAPPED overlappedSend;
		RIO_NOTIFICATION_COMPLETION completionTypeSend;

		completionTypeSend.Type = RIO_IOCP_COMPLETION;
		completionTypeSend.Iocp.IocpHandle = hIOCPSend;
		completionTypeSend.Iocp.CompletionKey = (void*)CK_START;
		completionTypeSend.Iocp.Overlapped = &overlappedSend;

		completionQueue_Send = l_rio.RIOCreateCompletionQueue(RIO_PENDING_SENDS, &completionTypeSend);
		if (completionQueue_Send == RIO_INVALID_CQ)
		{
			printf_s("RIOCreateCompletionQueue for Sending Error: %d\n", GetLastError());
			pthread_exit(0);
		}
	//}

		/// creating RIO RQ
		/// SEND and RECV with two CQs, seperately (can also be done with only 1 CQ)
		l_requestQueue = l_rio.RIOCreateRequestQueue(sock, RIO_PENDING_RECVS, 1, RIO_PENDING_SENDS, 1, completionQueue_Recv, completionQueue_Send, NULL);
		if (l_requestQueue == RIO_INVALID_RQ)
		{
			printf_s("RIOCreateRequestQueue Error: %d\n", GetLastError());
			pthread_exit(0);
		}

	/// registering RIO buffers for SEND
	{
		DWORD totalBufferCount = 0;
		DWORD totalBufferSize = 0;

		l_sendBufferPointer = AllocateBufferSpace(SEND_BUFFER_SIZE, RIO_PENDING_SENDS, &totalBufferSize, &totalBufferCount);
		l_sendBufferId = l_rio.RIORegisterBuffer(l_sendBufferPointer, totalBufferSize);
		if (l_sendBufferId == RIO_INVALID_BUFFERID)
		{
			printf_s("RIORegisterBuffer Error: %d\n", GetLastError());
			pthread_exit(0);
		}

		offset = 0;
		l_sendRioBufs = malloc(sizeof(EXTENDED_RIO_BUF) * totalBufferCount);
		l_sendRioBufTotalCount = totalBufferCount;

		for (i = 0; i < l_sendRioBufTotalCount; ++i)
		{
			/// split l_sendRioBufs to SEND_BUFFER_SIZE for each RIO operation
			pBuffer = l_sendRioBufs + i;
			pBuffer->operation = OP_SEND;
			pBuffer->BufferId = l_sendBufferId;
			pBuffer->Offset = offset;
			pBuffer->Length = SEND_BUFFER_SIZE;
			offset += SEND_BUFFER_SIZE;
		}
	}

	/// registering RIO buffers for ADDR
	{
		DWORD totalBufferCount = 0;
		DWORD totalBufferSize = 0;

		l_addrBufferPointer = AllocateBufferSpace(ADDR_BUFFER_SIZE, RIO_PENDING_RECVS, &totalBufferSize, &totalBufferCount);
		l_addrBufferId = l_rio.RIORegisterBuffer(l_addrBufferPointer, totalBufferSize);
		if (l_addrBufferId == RIO_INVALID_BUFFERID)
		{
			printf_s("RIORegisterBuffer Error: %d\n", GetLastError());
			pthread_exit(1);
		}

		offset = 0;

		l_addrRioBufs = malloc(sizeof(EXTENDED_RIO_BUF) *totalBufferCount);
		l_addrRioBufTotalCount = totalBufferCount;
		for (i = 0; i < totalBufferCount; ++i)
		{
			pBuffer = l_addrRioBufs + i;
			pBuffer->operation = OP_NONE;
			pBuffer->BufferId = l_addrBufferId;
			pBuffer->Offset = offset;
			pBuffer->Length = ADDR_BUFFER_SIZE;
			offset += ADDR_BUFFER_SIZE;
		}
	}

	/// registering RIO buffers for RECV and then, post pre-RECV
	{
		DWORD totalBufferCount = 0;
		DWORD totalBufferSize = 0;

		l_recvBufferPointer = AllocateBufferSpace(RECV_BUFFER_SIZE, RIO_PENDING_RECVS, &totalBufferSize, &totalBufferCount);
		l_recvBufferId = l_rio.RIORegisterBuffer(l_recvBufferPointer, totalBufferSize);
		if (l_recvBufferId == RIO_INVALID_BUFFERID)
		{
			printf_s("RIORegisterBuffer Error: %d\n", GetLastError());
			pthread_exit(1);
		}

		offset = 0;
		l_recvRioBufs = malloc(sizeof(EXTENDED_RIO_BUF) * totalBufferCount);
		l_recvRioBufTotalCount = totalBufferCount;

		for (i = 0; i < totalBufferCount; ++i)
		{
			pBuffer = l_recvRioBufs + i;
			pBuffer->operation = OP_RECV;
			pBuffer->BufferId = l_recvBufferId;
			pBuffer->Offset = offset;
			pBuffer->Length = RECV_BUFFER_SIZE;
			offset += RECV_BUFFER_SIZE;
		}
	}

	results = malloc(sizeof(RIORESULT) * RIO_MAX_RESULTS);
	sendResults = malloc(sizeof(RIORESULT) * RIO_MAX_RESULTS);
#endif // _WIN32

	printf("\tWorker-Thread Nr.%d is started.\n", ThreadInfo->ThreadNr);
	l_sendRioBufIndex = l_addrRioBufIndex = 0;

	if(OPMode == OP_SERVER)
		next_OPType = OP_RECVRESP;
	else if(OPMode == OP_SERVERONLY)
		next_OPType = OP_RECV;
	else if (OPMode == OP_CLIENT)
		next_OPType = OP_SENDRECV;
	else
		next_OPType = OP_SEND;

	if (bNotify)
		l_Flags = 0;
	else
		l_Flags = RIO_MSG_DONT_NOTIFY;

	if ((OPMode == OP_SERVER) || (OPMode == OP_SERVERONLY))
	{
		tommy_hashlin_init(&ClientLookup);
	}

	localClient.errCounter = localClient.retransmitCounter = localClient.pktCounter = localClient.PktNr = localClient.lastActPkt = localClient.avgRTT = localClient.maxRTT = 0;
	localClient.minRTT = 0xFFFFFFFFFFFFFFFF;

	ThreadInfo->RecvCounter = ThreadInfo->SendCounter = 0;
	while (bRunning) {
#ifdef _WIN32
		switch (next_OPType) {
		case OP_RECV:
			bRecvTimeOut = 0;

			if (!bRecvActive) {
				bRecvActive = 1;

				pRecvBufs = &(l_recvRioBufs[l_recvRioBufIndex]);
				recvOffset = l_recvBufferPointer + pRecvBufs->Offset;
				//memset(recvOffset, 0, RECV_BUFFER_SIZE);

				if (!l_rio.RIOReceiveEx(l_requestQueue, pRecvBufs, 1, NULL, &l_addrRioBufs[l_addrRioBufIndex], NULL, 0, l_Flags, pRecvBufs))
				{
					printf_s("RIOReceive Error: %d\n", GetLastError());
					ExitCode = 1;
					next_CMD = CMD_EXIT;
					break;
				}
			}
			if (bNotify) {
				if (bRecvActive < 2) {
					notifyResult = l_rio.RIONotify(completionQueue_Recv);
					if (notifyResult != ERROR_SUCCESS)
					{
						printf_s("RIONotify Error: %d\n", GetLastError());
						ExitCode = 1;
						next_CMD = CMD_EXIT;
						break;
					}

					bRecvActive = 2;
				}

				//if (!GetQueuedCompletionStatus(hIOCPRecv, &numberOfBytes, &completionKey, &pOverlapped, recvTimeout))
				if (!GetQueuedCompletionStatusEx(hIOCPRecv, &rcvOverlappedEntries, maxOverlappedEntries, &recvOvEntries, recvTimeout, FALSE))
				{
					lastError = GetLastError();
					//if ((recvTimeout != INFINITE) && (pOverlapped == NULL)) {
					if ((recvTimeout != INFINITE) && (lastError == WAIT_TIMEOUT)) {
						//Receive-Timeout reached,	GetLastError() == WAIT_TIMEOUT
						bRecvTimeOut = 1;

						if ((OPMode == OP_CLIENT) || (OPMode == OP_CLIENTONLY)) {
							if (next_CMD == CMD_WAIT_4_ACK)
								next_CMD = OP_RESEND;
							next_OPType = OP_SEND;
						}
						//Reset RIOBufferIndex
						l_sendRioBufIndex = 0;
						continue;
					}
					else {
						printf_s("GetQueuedCompletionStatusEx Error: %d\n", GetLastError());
						ExitCode = 1;
						next_CMD = CMD_EXIT;
						break;
					}
				}

				/// exit when CK_STOP
				// Code for GetQueuedCompletitionStatus:
				//if (completionKey == (ULONG_PTR)CK_STOP) {
				//	next_CMD = CMD_EXIT_MAINLOOP;
				//	break;
				//}
				if (recvOvEntries != 0)
					for (x = 0; x < recvOvEntries; x++) {
						if (rcvOverlappedEntries[x].lpCompletionKey == (ULONG_PTR)CK_STOP) {
							next_CMD = CMD_EXIT_MAINLOOP;
							break;
						}
					}

				memset(results, 0, sizeof(results));
				
				numResults = l_rio.RIODequeueCompletion(completionQueue_Recv, results, RIO_MAX_RESULTS);
			} else {   /* End of    bNotify */
				memset(results, 0, sizeof(results));

				recvStart = clock();
				do {
					numResults = l_rio.RIODequeueCompletion(completionQueue_Recv, results, RIO_MAX_RESULTS);
					if (numResults == 0) {
						if((recvTimeout != INFINITE) && ((clock() - recvTimeout) > recvTimeout)) {
							bRecvTimeOut = 1;
						} else
							YieldProcessor();
					}
					else
						break;
				} while ((numResults == 0) && (bRunning) && !bRecvTimeOut);

				if (bRecvTimeOut) {
					if ((OPMode == OP_CLIENT) || (OPMode == OP_CLIENTONLY)) {
						if (next_CMD == CMD_WAIT_4_ACK)
							next_CMD = OP_RESEND;
						next_OPType = OP_SEND;
					}
					//Reset RIOBufferIndex
					l_sendRioBufIndex = 0;

					continue;
				}
			}
			if (0 == numResults || RIO_CORRUPT_CQ == numResults)
			{
				if (RIO_CORRUPT_CQ == numResults) {
					printf_s("RIODequeueCompletion Error: %d\n", GetLastError());
					ExitCode = 1;
					next_CMD = CMD_EXIT;
					break;
				}
			}
			else {
				bRecvActive = 0;
				//Reset RIOBufferIndex for Addr-Buffers
				//l_recvRioBufIndex = l_addrRioBufIndex = l_sendRioBufIndex = 0;
			}

			if (debug)
				printf("INFO: %d Packets received.\n", numResults);
			for (i = 0; i < numResults; ++i)
			{
				ThreadInfo->RecvCounter++;

				pBuffer = results[i].RequestContext;
				ThreadInfo->RecvBytes += pBuffer->Length;
				recvOffset = l_recvBufferPointer + pBuffer->Offset;

				if ((OPMode == OP_SERVER) || (OPMode == OP_SERVERONLY)) {
					pAddrBufs = &(l_addrRioBufs[l_addrRioBufIndex % l_addrRioBufTotalCount]);
					addrOffset = l_addrBufferPointer + pAddrBufs->Offset;
					//ToDo:
					//	IPv6 is missing
					memcpy_s(&remoteClient, sizeof(remoteClient), addrOffset, sizeof(remoteClient));
					slen = 6;	//Port + IP-Address

					objClient = tommy_hashlin_search(&ClientLookup, &tommy_hash_cmpClientNode, &remoteClient, tommy_hash_u64(0, &(((struct sockaddr_in *)&remoteClient)->sin_port), slen));
					if (objClient == NULL) {
						//Insert new Client
						objClient = malloc(sizeof(struct ClientNode));
						memcpy_s(&(objClient->client), sizeof(struct sockaddr_in), &remoteClient, sizeof(remoteClient));
						objClient->PktNr = 0;
						objClient->lastActPkt = 0;
						objClient->pktCounter = 0;
						objClient->errCounter = 0;
						objClient->retransmitCounter = 0;
						objClient->minRTT = 0;
						objClient->avgRTT = 0;
						objClient->maxRTT = 0;
						tommy_hashlin_insert(&ClientLookup, &objClient->node, objClient, tommy_hash_u64(0, &(((struct sockaddr_in *)&remoteClient)->sin_port), slen));
					}

					//Check incomming Packet
					if (pBuffer->Length < minPktLength) {
						objClient->errCounter++;
						if (debug)
							printf("INFO: Packet was too short.\n");
					}
					else {
						//Client-Statistics
						objClient->pktCounter++;

						PktNr = pm_ntohll(((PKT_HEADER *)recvOffset)->PktNr);
						if (((PKT_HEADER *)recvOffset)->PktType == (char)PKT_ACK) {
							objClient->lastActPkt = PktNr;

							if (debug)
								printf("INFO: Ack for PktNr.: %d received.\n", PktNr);
						}
						else {
							if (debug)
								printf("INFO: PktNr.: %d received.\n", PktNr);

							//Set Target-Address:
							l_addrRioBufIndex++;
							pAddrBufs = &(l_addrRioBufs[l_addrRioBufIndex % l_addrRioBufTotalCount]);
							addrOffset = l_addrBufferPointer + pAddrBufs->Offset;
							memcpy_s(addrOffset, ADDR_BUFFER_SIZE, &(objClient->client), sizeof(objClient->client));

							if ((objClient->PktNr + 1) < PktNr) {
								//Packet lost !!!
								objClient->errCounter += (PktNr - objClient->PktNr);
								if (debug)
									printf("INFO: Packets between Nr.: %d - %d are lost.\n", objClient->PktNr, PktNr);

								if (WndSize) {
									//	Send Ack for last received Packet...
									l_sendRioBufIndex++;
									sendBuf = &(l_sendRioBufs[l_sendRioBufIndex % l_sendRioBufTotalCount]);
									sendBuf->Length = PktSize;
									sendOffset = l_sendBufferPointer + sendBuf->Offset;
									memcpy_s(sendOffset, SEND_BUFFER_SIZE, sndBuffer, PktSize);

									((PKT_HEADER*)sendOffset)->PktType = (char)PKT_ACK;
									((PKT_HEADER*)sendOffset)->PktNr = htonll(objClient->PktNr);
									((PKT_HEADER*)sendOffset)->ThrNr = htonl(ThreadInfo->ThreadNr);
									((PKT_HEADER*)sendOffset)->PktLength = htonll(0);
									numSendResults = netSend(&l_rio, sendResults, hIOCPSend, completionQueue_Send, l_requestQueue, sendBuf, NULL, pAddrBufs, bNotify);
									if (bNotify || bSndChkResult) {
										if (0 == numSendResults || RIO_CORRUPT_CQ == numSendResults)
										{
											printf_s("RIODequeueCompletion Error: %d\n", GetLastError());
											ExitCode = 1;
											next_CMD = CMD_EXIT_MAINLOOP;
											break;
										}
										for (i = 0; i < numSendResults; i++) {
											if (sendResults[i].Status != 0) {
												localClient.errCounter++;

												printf("Error: Sending data failed !\n");
												//next_OPType = last_OPType;
											}
											else {
												objClient->lastActPkt = objClient->PktNr;

												if (debug)
													printf("INFO: Ack-Packet %d sent.\n", objClient->PktNr);
												ThreadInfo->SendCounter++;
												ThreadInfo->SendBytes += ((EXTENDED_RIO_BUF*)sendResults[i].RequestContext)->Length;
											}
										}
									}
									else {
										ThreadInfo->SendCounter++;
										ThreadInfo->SendBytes += PktSize;

										if (debug)
											printf("INFO: Ack-Packet %d sent.\n", objClient->PktNr);
									}
								} //if(WndSize)
								else {
									objClient->PktNr = PktNr;
								}
							}
							else if ((objClient->lastActPkt > objClient->PktNr) && (objClient->PktNr <= WndSize)) {
								//Client was restarted...
								objClient->lastActPkt = 0;
							}
							else {
								objClient->PktNr = PktNr;
								if ((WndSize && (
									((objClient->PktNr - objClient->lastActPkt) >= WndSize)) ||
									((objClient->lastActPkt > objClient->PktNr) && (objClient->PktNr >= WndSize)) ) ||
									(((PKT_HEADER *)recvOffset)->PktType == (char)PKT_DATARETRANSMIT) ) {
									//	Send Ack-Packet back to Client
									l_sendRioBufIndex++;
									sendBuf = &(l_sendRioBufs[l_sendRioBufIndex % l_sendRioBufTotalCount]);
									sendBuf->Length = PktSize;
									sendOffset = l_sendBufferPointer + sendBuf->Offset;
									memcpy_s(sendOffset, SEND_BUFFER_SIZE, sndBuffer, PktSize);

									((PKT_HEADER*)sendOffset)->PktType = (char)PKT_ACK;
									((PKT_HEADER*)sendOffset)->PktNr = htonll(objClient->PktNr);
									((PKT_HEADER*)sendOffset)->ThrNr = htonl(ThreadInfo->ThreadNr);
									((PKT_HEADER*)sendOffset)->PktLength = htonll(0);
									numSendResults = netSend(&l_rio, sendResults, hIOCPSend, completionQueue_Send, l_requestQueue, sendBuf, NULL, pAddrBufs, bNotify);
									if (bNotify || bSndChkResult) {
										if (0 == numSendResults || RIO_CORRUPT_CQ == numSendResults)
										{
											printf_s("RIODequeueCompletion Error: %d\n", GetLastError());
											ExitCode = 1;
											next_CMD = CMD_EXIT_MAINLOOP;
											break;
										}
										for (i = 0; i < numSendResults; i++) {
											if (sendResults[i].Status != 0) {
												localClient.errCounter++;

												printf("Error: Sending data failed !\n");
												//next_OPType = last_OPType;
											}
											else {
												objClient->lastActPkt = objClient->PktNr;

												if (debug)
													printf("INFO: Ack-Packet %d sent.\n", objClient->PktNr);
												ThreadInfo->SendCounter++;
												ThreadInfo->SendBytes += ((EXTENDED_RIO_BUF*)sendResults[i].RequestContext)->Length;
											}
										}
									}
									else {
										ThreadInfo->SendCounter++;
										ThreadInfo->SendBytes += PktSize;

										if (debug)
											printf("INFO: Ack-Packet %d sent.\n", objClient->PktNr);
									}
								}
							}
						}
					}
				}	// if((OPMode == OP_SERVER
				else if ((OPMode == OP_CLIENT) || (OPMode == OP_CLIENTONLY)) {
					if (next_CMD == CMD_WAIT_4_ACK) {
						if (((PKT_HEADER *)recvOffset)->PktType == (char)PKT_ACK) {
							localClient.respTime = getTimeMSec();
							PktNr = pm_ntohll(((PKT_HEADER *)recvOffset)->PktNr);
							localClient.lastActPkt = PktNr;

							deltaTime = localClient.respTime - localClient.sendTime;
							if (debug)
								printf("INFO: Ack for PktNr.: %d received, RTT=%.2f.\n", PktNr, deltaTime);
							if (localClient.minRTT > deltaTime)
								localClient.minRTT = deltaTime;
							else if (localClient.maxRTT < deltaTime)
								localClient.maxRTT = deltaTime;
							if (localClient.avgRTT == 0) {
								localClient.avgRTT += deltaTime;
							}
							else {
								localClient.avgRTT += deltaTime;
								localClient.avgRTT = localClient.avgRTT / 2;
							}

							//if (localClient.lastActPkt < localClient.PktNr) {
								//We have lost Packets...
								//	resend this Packets
								//localClient.PktNr = localClient.lastActPkt;
							//}

							//next_CMD = CMD_NONE;
						}
						else {
							//next_CMD = CMD_UNKNOWN;
						}
					}

					next_OPType = OP_SEND;
				}
			} //for (i = 0; i < numResults; ++i)

			if ((OPMode == OP_CLIENT) || (OPMode == OP_CLIENTONLY)) {
				if (next_CMD == CMD_WAIT_4_ACK) {
					if (localClient.lastActPkt < localClient.PktNr) {
						//We have lost Packets...
						//	resend this Packets
						localClient.PktNr = localClient.lastActPkt;
						localClient.retransmitCounter++;
					}

					next_CMD = CMD_NONE;
				}
				next_OPType = OP_SEND;
			}

			//Reset RIOBufferIndex for Addr-Buffers
			l_recvRioBufIndex = l_addrRioBufIndex = l_sendRioBufIndex = 0;
			break;
		case OP_SEND:
			//Set Target-Address:
			l_addrRioBufIndex++;
			pAddrBufs = &(l_addrRioBufs[l_addrRioBufIndex % l_addrRioBufTotalCount]);
			addrOffset = l_addrBufferPointer + pAddrBufs->Offset;
			memcpy_s(addrOffset, ADDR_BUFFER_SIZE, &remoteServer, sizeof(remoteServer));

			if (next_CMD == OP_RESEND) {
				l_sendRioBufIndex++;
				sendBuf = &(l_sendRioBufs[l_sendRioBufIndex % l_sendRioBufTotalCount]);
				sendBuf->Length = PktSize;
				sendOffset = l_sendBufferPointer + sendBuf->Offset;
				memcpy_s(sendOffset, SEND_BUFFER_SIZE, sndBuffer, PktSize);

				((PKT_HEADER*)sendOffset)->PktType = (char)PKT_DATARETRANSMIT;
				((PKT_HEADER*)sendOffset)->PktNr = htonll(localClient.PktNr);
				((PKT_HEADER*)sendOffset)->ThrNr = htonl(ThreadInfo->ThreadNr);
				((PKT_HEADER*)sendOffset)->PktLength = htonll(PktSize);
				localClient.sendTime = getTimeMSec();

				if (!l_rio.RIOSendEx(l_requestQueue, sendBuf, 1, NULL, pAddrBufs, NULL, NULL, l_Flags, sendBuf))
				{
					printf_s("RIOSend Error: %d\n", GetLastError());
					pthread_exit(1);
				}
				else if (debug)
					printf("INFO: PktNr.: %d will be resent.\n", localClient.PktNr);

				localClient.pktCounter++;
				localClient.retransmitCounter++;
				ThreadInfo->SendCounter++;
				ThreadInfo->retransmitCounter++;
				ThreadInfo->SendBytes += PktSize;

				next_CMD = CMD_WAIT_4_ACK;
				next_OPType = OP_RECV;
			}
			else {
				//ToDo:
				//	if RIO_PENDING_SENDS < l  => Need more RIOSendEx-Cycles
				if (PktSize > SEND_BUFFER_SIZE) {
					l = PktSize / SEND_BUFFER_SIZE;
					if ((l* SEND_BUFFER_SIZE) < PktSize) {
						saved = PktSize - (l* SEND_BUFFER_SIZE);
						l++;
					}
					rc = SEND_BUFFER_SIZE;
				}
				else {
					l = 1;
					rc = PktSize;
				}
				offset = 0;
				for (i = 0; i < l; i++) {
					l_sendRioBufIndex++;
					sendBuf = &(l_sendRioBufs[l_sendRioBufIndex % l_sendRioBufTotalCount]);
					sendBuf->Length = rc;
					sendOffset = l_sendBufferPointer + sendBuf->Offset;
					memcpy_s(sendOffset, SEND_BUFFER_SIZE, sndBuffer + offset, rc);

					((PKT_HEADER*)sendOffset)->PktType = (char)PKT_DATA;
					((PKT_HEADER*)sendOffset)->PktNr = htonll(localClient.PktNr + 1 + i);
					((PKT_HEADER*)sendOffset)->ThrNr = htonl(ThreadInfo->ThreadNr);
					((PKT_HEADER*)sendOffset)->PktLength = htonll(PktSize);
					localClient.sendTime = getTimeMSec();

					if (!l_rio.RIOSendEx(l_requestQueue, sendBuf, 1, NULL, pAddrBufs, NULL, NULL, l_Flags, sendBuf))
					{
						printf_s("RIOSend Error: %d\n", GetLastError());
						pthread_exit(1);
					}
					else if (debug)
						printf("INFO: PktNr.: %d will be sent.\n", localClient.PktNr + 1 + i);

					localClient.pktCounter++;
					localClient.PktNr++;
					ThreadInfo->SendCounter++;
					ThreadInfo->SendBytes += PktSize;

					if (WndSize && ((localClient.PktNr - localClient.lastActPkt) >= WndSize)) {
						next_CMD = CMD_WAIT_4_ACK;
						next_OPType = OP_RECV;
					}

					offset += rc;
					if ((i + 1) == l)
						rc = saved;
				}
			}
			if (bNotify) {
				//Notify for Sending-Ready
				notifyResult = l_rio.RIONotify(completionQueue_Send);
				if (notifyResult != ERROR_SUCCESS)
				{
					printf_s("RIONotify Error: %d\n", GetLastError());
					ExitCode = 1;
					next_CMD = CMD_EXIT_MAINLOOP;
					break;
				}

				if (!GetQueuedCompletionStatus(hIOCPSend, &numberOfBytes, &completionKey, &pOverlapped, INFINITE))
				{
					printf_s("GetQueuedCompletionStatus Error: %d\n", GetLastError());
					ExitCode = 1;
					next_CMD = CMD_EXIT_MAINLOOP;
					break;
				}

				/// exit when CK_STOP
				if (completionKey == (ULONG_PTR)CK_STOP) {
					next_CMD = CMD_EXIT_MAINLOOP;
					break;
				}
			}

			memset(sendResults, 0, sizeof(sendResults));
			if(bNotify) {
				numSendResults = l_rio.RIODequeueCompletion(completionQueue_Send, sendResults, RIO_MAX_RESULTS);
			}
			else {
				if (bSndChkResult) {
					do {
						numSendResults = l_rio.RIODequeueCompletion(completionQueue_Send, sendResults, RIO_MAX_RESULTS);
						/* if (numSendResults == 0)
							YieldProcessor();
						else
							break;
						*/
					} while (numSendResults == 0);
				}
				else
					numSendResults = 1;
			}
			if (0 == numSendResults || RIO_CORRUPT_CQ == numSendResults)
			{
				printf_s("RIODequeueCompletion Error: %d\n", GetLastError());
				ExitCode = 1;
				next_CMD = CMD_EXIT_MAINLOOP;
				break;
			}
			if (bNotify || bSndChkResult) {
				//Check Sendresults
				for (i = 0; i < numSendResults; i++) {
					if (sendResults[i].Status != 0) {
						localClient.errCounter++;

						printf("Error: Sending data failed !\n");
						//next_OPType = last_OPType;
					}
					else {
						if (debug)
							printf("INFO: %d Packets sent, %d Bytes sent.\n", numSendResults, sendResults[0].BytesTransferred);

						/*
						localClient.pktCounter++;
						localClient.PktNr++;
						ThreadInfo->SendCounter++;
						pBuffer = sendResults[i].RequestContext;
						ThreadInfo->SendBytes += pBuffer->Length;

						if (WndSize && ((localClient.PktNr - localClient.lastActPkt) >= WndSize)) {
							next_CMD = CMD_WAIT_4_ACK;
							next_OPType = OP_RECV;
						}
						*/
					}
				}
			}
			//Reset l_sendRioBufIndex
			l_recvRioBufIndex = l_addrRioBufIndex = l_sendRioBufIndex = 0;
			break;
		default:
			break;
		}

		if (next_CMD == CMD_EXIT) {
			goto WorkerThreadEnd;
		}
		else if (next_CMD == CMD_EXIT_MAINLOOP) {
			break;
		}
#endif // _WIN32
	}

WorkerThreadEnd:
#ifdef _WIN32
	//RIO Cleanup
	l_rio.RIOCloseCompletionQueue(completionQueue_Recv);
	l_rio.RIOCloseCompletionQueue(completionQueue_Send);
	l_rio.RIODeregisterBuffer(l_sendBufferId);
	l_rio.RIODeregisterBuffer(l_recvBufferId);
	l_rio.RIODeregisterBuffer(l_addrBufferId);
	//free(...);
	free(results);
#endif // _WIN32

	free(sndBuffer);

	ThreadInfo->minRTT = localClient.minRTT;
	ThreadInfo->avgRTT = localClient.avgRTT;
	ThreadInfo->maxRTT = localClient.maxRTT;

	if ((OPMode == OP_SERVER) || (OPMode == OP_SERVERONLY))
	{
		//Print Statistics
		tommy_hashlin_foreach(&ClientLookup, tommy_print_ClientNodeStatistics);

		// deallocates all the objects iterating the hashtable
		tommy_hashlin_foreach(&ClientLookup, free);
		// deallocates the hashtable
		tommy_hashlin_done(&ClientLookup);
	}

	pthread_exit(NULL);  //ExitCode
}

#ifdef _WIN32
BOOL WINAPI HandlerRoutine(_In_ DWORD dwCtrlType) {
	switch (dwCtrlType)
	{
	case CTRL_SHUTDOWN_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_C_EVENT:
		printf("[Ctrl]+C\n");
		pthread_mutex_lock(&mutex_mainloop);
		printf("\texiting program...\n");
		bRunning = FALSE;
		pthread_cond_signal(&cond_mainloop);
		pthread_mutex_unlock(&mutex_mainloop);
		// Signal is handled - don't pass it on to the next handler
		return TRUE;
	default:
		// Pass signal on to the next handler
		return FALSE;
	}
}
#else
void  HandlerRoutine(int sig)
{
	char  c;

	signal(sig, SIG_IGN);
	printf("[Ctrl]+C\n");
	bRunning = false;
	//	"Do you really want to quit? [y/n] ");
	//c = getchar();
	//if (c == 'y' || c == 'Y')
	//	exit(0);
	//else
	//	signal(SIGINT, INThandler);
	//getchar(); // Get new line character
}
#endif

void endprog(int ExitVal) {
	u_int32_t i = 0;
	u_int64_t RecvPkt = 0, SendPkt = 0, RecvByteSum = 0, SendByteSum = 0, RetransSum = 0;

	if (pThreadParams != NULL) {
		for (i = 0; i < maxThreads; i++) {
#ifdef _WIN32
			if (0 == PostQueuedCompletionStatus(pThreadParams[i].hIOCP, 0, CK_STOP, 0))
			{
				printf_s("PostQueuedCompletionStatus Error: %d\n", GetLastError());
			}
#endif

			//pthread_cond_signal(&curlThreadInfos[curlThreadNo].cond);
			if (pThreadParams[i].hThread != NULL) {
				pthread_join(pThreadParams[i].hThread, NULL);
				//pthread_mutex_destroy(&curlThreadInfos[curlThreadNo].mutex);
				//pthread_cond_destroy(&curlThreadInfos[curlThreadNo].cond);
			}
			pThreadParams[i].ThreadNr = -1;
		}

		//Print Statistics:
		printf("Thread-Nr\tPackets-Recv\tPackets-Sent\tBytes-Recv\tBytes-Sent\tRetrans.\tmin-RTT\tavgRTT\tmaxRTT\n");
		for (i = 0; i < maxThreads; i++) {
			printf("%*d\t%*d\t%*d\t%d\t%d\t%d\t%d\t%d\t%d\n", 9, i, 15, pThreadParams[i].RecvCounter, 15, pThreadParams[i].SendCounter, pThreadParams[i].RecvBytes, pThreadParams[i].SendBytes, pThreadParams[i].retransmitCounter, pThreadParams[i].minRTT, pThreadParams[i].avgRTT, pThreadParams[i].maxRTT);
			RecvPkt += pThreadParams[i].RecvCounter;
			SendPkt += pThreadParams[i].SendCounter;
			RecvByteSum += pThreadParams[i].RecvBytes;
			SendByteSum += pThreadParams[i].SendBytes;
			RetransSum += pThreadParams[i].retransmitCounter;

			pThreadParams[i].ThreadNr = -1;
		}
		printf("=======================================================================================================\n");
		printf("Sum:     \t%*d\t%*d\t%d\t%d\t%d\n", 15, RecvPkt, 15, SendPkt, RecvByteSum, SendByteSum, RetransSum);
		printf("Runtime (meassured with Clockcycles) was %f seconds.\n", runTime);
		printf("Runtime (meassured with Timefunction) was %.2f seconds.\n", difftime(endTime1, startTime1));


		free(pThreadParams);
		pThreadParams = NULL;
	}

#ifdef _WIN32
	if (MainSock != INVALID_SOCKET) {
			//shutdown(MainSock, SD_BOTH);
			closesocket(MainSock);
			MainSock = INVALID_SOCKET;
	}
	WSACleanup();
#else
	if (MainSock >= 0) {
		close(MainSock);
}
#endif // _WIN32

	pthread_mutex_destroy(&mutex_mainloop);
	pthread_cond_destroy(&cond_mainloop, NULL);
	//pthread_exit(NULL);
	exit(ExitVal);
}
