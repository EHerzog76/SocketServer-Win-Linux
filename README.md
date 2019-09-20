# SocketServer-Win-Linux
UDP-/TCP-Server and Client to test how many packets can be transmitted and received over your Network.
In the current version the main focus was to use the RIO-Networkfunctions on Windows 8, Windows Server 2012 and above.


## Usage examples for Windows:
### Throughput-Test:
	Servermode:
		IPPerfTest.exe -P UDP -L 0.0.0.0 -p 3000 -w 0 -T 1 -l 64 [-N]

	Clientmode:
		IPPerfTest.exe -P UDP -S <Server-IP> -s 3000 -w 0 -T 2 -l 64 [-N]
### Receive-/Transmit-Test:
	Servermode:
		IPPerfTest.exe -P UDP -L 0.0.0.0 -p 3000 -w 1 -T 1 -l 64 -t 2 [-N]

	Clientmode:
		IPPerfTest.exe -P UDP -S <Server-IP> -s 3000 -w 1 -T 2 -l 64 -t 2 [-N]

### Arguments:
```
IPPerfTest.exe -h
THB-IPPerf, IPPerf 1.0.0.0 (20190814)
Usage: IPPerfTest.exe [ -d ] [ -P TCP|UDP ] [ -L IP address ] [ -p port ] [ -S Target-Server ] [ -s Target-Serverport ] [ , ... ] ]
       IPPerfTest.exe [ -h ]

General options:
  -h    Show this page.
  -V    Show version and compile-time options and exit.
  -P    Use UDP or TCP as Protocol.
  -L    Bind to the specified IP address.
  -p    Listen on the specified port.
  -S    Operate in client-Mode and send packets to Server IP.
  -s    Remote-Server-Port.
  -n    Send number of Packets.
  -l    Packetsize in 64Byte steps.
  -w    Windowsize, how many Data-Packet can be sent without an Ack-Packet, 0=disabled.
  -t    Receive-Timeout in msec, default=1000msec.
  -T    Number of Threads to use. If not specified the number of Threads will be calculated by the number of CPUs.
  -N    enable Receive-Notify RIONotify will be enabled and also Check Sendresults -C.
  -C    Check and wait for local Sendresults.
  -d    Enable debug

For suggestions, critics, bugs, contact me: Erwin Herzog <e.herzog76@live.de>.
```
