Who knew what an odyssey it'd be just figuring out a couple useful quick port selection lists!  A quick look into a multitude of "common ports" docs on the 'net revealed a just gob of conflicting, and in some instances, flat-out *wrong* information. In response (for better or for worse), I reconciled that pile of crap into this best-estimate of common and/or interesting port numbers. Use it when you don't have the time, inclination, or patience to scan 65535 ports on every host. 

These are what's used in Netscanx's tcp_short, tcp_extra, and udp_short port specifications. FWIW, I also have ports 0-1023 (admin) and ALL (0-65535) on tap as well.
*--ctg* 

### TCP shortlist of commn/interesting ports {"tcp_short"}
____
20 FTP
21 FTP 
22 SSH 
23 Telnet 
25 SMTP 
43 whois 
53 DNS 
67 DHCP/bootp
68 DHCP/bootp 
69 TFTP 
79 Finger 
80 HTTP 
88 Kerberos 
110 POP3 
111 sunrpc 
113 Ident 
119 nntp 
135 MS DCE/RPC 
137 MS NetBIOS Name Svc
139 MS NetBIOS Session Svc
143 IMAP4 
177 XDMCP Login 
179 BGP 
389 LDAP 
443 HTTPS 
445 Microsoft DS 
464 Kerberos KDC 
512 rexec 
513 rlogin 
514 syslog
515 LPD/LPR Printer 
546 DHCPv6
547 DHCPv6 
587 SMTP Submission 
593 http-rpc-epmap 
636 LDAP over SSL
853 DNS over TLS 
873 rsync 
989 FTP over SSL
990 FTP over SSL 
993 IMAP over SSL 
995 POP Over SSL
1270 MS SCOM
1337 OMG so Leet
1433 Microsoft SQL
1434 Microsoft SQL 
1521 Oracle DB
2222 SSH-alt
2323 Telnet-alt
2375 Docker REST API plaintext
2483 Oracle DB
2484 Oracle DB SSL
3306 MySQL
3333 Eggdrop IRC
3389 MS Terminal Server
5060 SIP
5061 SIP TLS
5432 PostgreSQL
5800 VNC over HTTP
5900 VNC
8008 httpd alt
8080 Apache Tomcat
8081 Sun Proxy Admin Service
8088 httpd alt
8443 Apache Tomcat SSL

### List of extra interesting TCP ports {"tcp_extra"}
____
37 time
49 TACACS
70 Gopher
82 xfer 
83 mit-ml-dev 
85 mit-ml-dev
109 POP2
115 Simple File Transfer
162 SNMP Trap
201 Appletalk 
220 IMAPv3
264 BGP Multicast/bgmp
444 snpp 
464 Kerberos Change/Set password 
497 Retrospect backup
530 RPC
543 kerberos login
544 kerberos remote shell
601 rsyslog
631 Internet Printing/CUPS
639 Multicast Source Discovery
666 aircrack-ng
749 Kerberos Admin
750 kerberos-iv 
751 Kerberos Auth/kerberos_master
752 Kerberos kpasswd 
843 Adobe Flash
902 VMWare ESXi
903 VMWare ESXi
992	Telnet SSL
1080 SOCKS proxy
1194 OpenVPN
1514 rsyslog
1701 L2TP
1723 PPTP
1741 cisco-net-mgmt
1812 RADIUS
1813 RADIUS
2049 NFS
2082 cPanel
2083 cPanel SSL
2095 cPanel Webmail
2096 cPanel Webmail SSL
2100 Oracle XDB
2376 Docker REST API SSL
2638 SQL Anywhere
3128 Squid Proxy
3268 MS global catalog LDAP
3269 MS global catalog SSL
3689 Apple iTunes/Airplay
4333 mSQL
4444 Metasploit listener
5000 ? Multiuse
6514 Syslog TLS
6881 Bit Torrent
8000 http-alt
8089 Radan HTTP
6000 x11
6001 x11
6665 IRC
6666 IRC
6667 IRC
6668 IRC
6669 IRC
8333 Bitcoin
8334 Bitcoin
8888 HyperVM
9001 Tor
9333 Litecoin
10000 Webmin
12345 NetBus remote
18080 Monero
18081 Monero RPC
19132 Minecraft
20000 Usermin
31337 So Leetx0r

### UDP short list of common/interesting ports {"udp_short"}
____
67 DHCP/bootp
68 DHCP/bootp
69 TFTP
123 NTP 
138 MS NetBIOS Datagram Svc
161 SNMP
162 SNMP Trap
264 BGP Multicast/bgmp
500 ISAKMP/IKE
514 syslog 
520 RIP 
521 RIPng 
853 DNS over TLS
902 VMWare ESXi
1433 Microsoft SQL
1434 Microsoft SQL
1812 RADIUS
1813 RADIUS 
2049 NFS
3268 MS global catalog LDAP
3269 MS global catalog SSL
3260 iSCSI Target
3478 Ms Teams/Skype
3479 Ms Teams/Skype
3480 MS Teams/Skype
3481 MS Teams/Skype
4500 IPSec NAT Traversal
4567 tram
5000 UPnP
5001 ?
5060 SIP
10000 BackupExec
11371 OpenPGP HTTP Key Server
