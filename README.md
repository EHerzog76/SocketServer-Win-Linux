# SocketServer-Win-Linux
UDP-/TCP-Server and Client to test how many packets can be transmitted and received over your Network.

##Usage examples for Windows:
###Throughput-Test:
	Servermode:
		IPPerfTest.exe -P UDP -L 0.0.0.0 -p 3000 -w 0 -T 1 -l 64 -N

	Clientmode:
		IPPerfTest.exe -P UDP -S <Server-IP> -s 3000 -w 0 -T 2 -l 64 -N
###Receive-/Transmit-Test:
	Servermode:
		IPPerfTest.exe -P UDP -L 0.0.0.0 -p 3000 -w 1 -T 1 -l 64 -t 2 -N

	Clientmode:
		IPPerfTest.exe -P UDP -S <Server-IP> -s 3000 -w 1 -T 2 -l 64 -t 2 -N
