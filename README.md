## Tracemore

Tracemore is a network measurement tool belonging to [traceroute ](http://traceroute.sourceforge.net/)/[ tracebox](http://www.tracebox.org) family: it implements their well known methodology with an extra level of flexibilty and also integrates it with a server-based approach and number of different modes and tests that make it a all-round network measurement tools.

Due to its flexibility Tracemore is especially intended to test new features and new protocols (for instance MPTCP, TCP Fast Open or the upcoming UDP Options). 

Usual transport protocols, TCP (along with its Options), UDP and ICMP are widely supported and every single field of their headers can be customized. 
Tracemore also allows the use of other transport protocols with a minor tweaking.
Also every field of IPv4 and IPv6 headers can be customized.

Customizing every single bit of a packet may seem unnecessary but instead gives the chance to test unusual scenarios in order to highlight network problems unnoticed with regular packets or detect and locate --- transparent middleboxes.

Tracemore descends from the Core of [Mobile Tracebox](---), an Android app developed by Raffaele Zullo that embodies tracebox methodology. 
The app has been originally presented along with a novel middlebox detection methodology in the following paper: Raffaele Zullo, Antonio Pescapé, Korian Edeline, Benoit Donnet - Hic Sunt NATs: Uncovering Address Translation With a Smart Traceroute.



## Linux

Tracemore can be easily compiled on Linux host. No library is used to forge and capture packets: the app only relies on raw and non-raw sockets to execute the tests.



## Android

Tracemore can be also compiled for Android using Android NDK: in this wats all platforms are supported: ARM, ARM64, x86_64, MIPS, MIPS64.

Android app is available on [Google Play](https://play.google.com/store/apps/details?id=be.ac.ulg.mobiletracebox) and is always updated with the last version of Tracemore as Core: it also embodies a user friendly GUI to easily select and customize the tests.



## Web page
A subset of tests will be also available to users through a Javascript/webRTC web page [www.middleboxes.com/tracemore.me](www.middleboxes.com/tracemore.me)



## Usage
### Joining two MPTCP flows
The 1st test shows a real multipath communication between our host and a MPTCP server. MPTCP connection is established on the first flow (MP_CAPABLE Syn, MP_CAPABLE Ack) on one TCP flow and MPTCP data is actually sent on this flow and Acked at TCP and MPTCP level (DSS, DSS Ack), then a new flow originated from a different source port joins the existing connection (MP_JOIN Syn -> MP_JOIN Syn Ack). The test is designed in this way for two reasons: i) without exchanging a well formed DSS packet MPTCP stack doesn't accept new flows so MP_JOIN couldn't be tested; ii) middleboxes can be transparent to TCP Options on Syn packet but then interfere with the same Option on the following packets.

```markdown
 0:  192.168.42.7   [TCP Syn] TCP::SourcePort(24d2)  TCP::Option_MPTCP(00811000000000000000)
64:  130.104.230.45 [TCP Syn Ack] TCP::Option_MPTCP (00810c4d5dfc94d0a464)

 0:  192.168.42.7   [TCP Ack]  TCP::SourcePort(24d2) TCP::Option_MPTCP(008110000000000000000c4d5dfc94d0a464)
64:  *

 0:  192.168.42.7   [TCP Ack 72 bytes] TCP::SourcePort(24d2) TCP::SeqNumber(01300001) TCP::Option_MPTCP(2004fb4e435d0000000100483aca)  TCP::Payload ("GET / HTTP/1.1...")
64:  130.104.230.45 [TCP Ack]  TCP::AckNumber(01300001) TCP::Option_MPTCP(3608200106a8308f000102163efffec5c815)
64:  130.104.230.45 [TCP Ack]  TCP::AckNumber(01300049) TCP::Option_MPTCP(2001fb4e43a5)

 0:  192.168.1.102  [TCP Syn] TCP::SourcePort (cefc) TCP::Option_MPTCP(10023a03caf210000000)
64:  130.104.230.45 [TCP Syn Ack] TCP::Option_MPTCP (100256c7a377b2e33fdaa29163c5)
```

### Detecting middleboxes (NAT, MPLS tunnel) through traceroute
The 2nd  test combines traceroute with server-based mode proving how an error in the ICMP quoted packet's UDP Checksum can be linked to NAT manipulation as demostrade in _Hic Sunt Nats_. The test also shows the presence of a MPLS tunnel.

```markdown
Traceroute
0:  100.115.103.10  [UDP]  UDP::SourcePort (cf21)  
1:  *  
2:  172.31.9.41     [8/8]  IP::DSCP/ECN (00->30)  IP::Checksum (75ea->76ba)  
3:  172.20.3.84     [8/8]  
4:  172.31.25.13    [8/8]  UDP::Checksum (ee84->4dd1)  !UDP::Checksum (wrg +0000->+a0b3)  
5:  172.17.160.145  [8/8 !ICMP::Multipart]  
6:  172.17.5.121    [8/8 !ICMP::Multipart]  !IP::TTL (2)  
7:  172.17.11.113   [8/8 !ICMP::Multipart]  !IP::TTL (3)  
8:  172.17.48.62    [8/8]  
9:  213.26.252.22   [8/8]  
10: 212.25.170.134  [8/8]  
11: 212.25.170.129  [8/8]  
12: 212.25.170.136  [8/8]  
13: 212.25.160.111  [8/8]  
14: 212.25.162.80   [UDP]  

Server-based
0:  100.115.103.10  [UDP]  IP::TTL (e)  UDP::SourcePort (cf21)  !UDP::Checksum (wrg a0b3)  
14: 212.25.162.80   [8/8]  IP::DSCP/ECN (00->30)  IP::TTL (0e->01)  IP::SourceAddr (100.115.103.10->158.148.205.156)  IP::Checksum (69ea->d606)  UDP::SourcePort (cf21->27ae)  UDP::Checksum (ee84->4dd1) 
```



## Source
Source code will be made avaiable in the next weeks on tracemore [github repository](https://github.com/raffaelezullo/tracemore/).
