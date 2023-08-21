/******************************************************************************
* netscanx
*
* Network scanner written in Go, mostly to see if Go concurrency gives us any
* advantage. Also, fun to see how far I can get network-features-wise.
* Apologies to Fyodor LOL. Nmap is still and will likely remain, the bomb ;)
*
* 		The basis for the largest feature is the TCP protocol, of course!
*  		                                                   |
* 		SYN-> <-SYN/ACK ACK-> ::  OPEN PORT                |
* 		SYN-> <-RST           ::  CLOSED PORT   <----------+
* 		SYN-> (timeout)       ::  FILTERED PORT
*
* The rest, I'll make up as I see fit, by whatever entertains me most >8]
*
* 14AUG2023
* CT Geigner ("chux0r")
*
*
* We'll use the standard "Dial" function (Dial? really?. Who named this mofo,
* AT&T? "TCPConnect" would be a great name for this, and I spent waaaay too much
* time in the "net" Go std package library before I realized that "Dial" as what I
* was seeking. Whatever. What else is new in computer hell these days? Nothin,
* that's what =)
*
* Src: https://pkg.go.dev/net@go1.21.0
*
* "Nice to have" neato features hit-list:
* ------------------------------------------------------
* UDP scanning (DialUDP)
* more integration using stdlib net structures and interfaces
* ICMP scanning/host ping and other ICMP uses
* Hardware address/local network tomfoolery
* Multicast fun
* BGP fun
* DNS fun
* SSL cert eval, and validation
* IP history & "associations"
* Packet & Flags constructor
******************************************************************************/
package main

import (
	"fmt"
	"net"
	"sync"
)

type TargetSpec struct {
	Addr string // names or IPs in string fmt == we should use net.Addr.String() for each element
	Ip   net.IP // []byte, it's the methods we want, really
	//Mac  net.HardwareAddr // layer 2; local net
}

type NetSpec struct {
	Protocol string   // "tcp" - expand into "ProtoSpec" later to accommodate UDP, ICMP/Type/Subtype
	PortList []uint16 // all der portz
	//Flags    net.Flags		// xmas comes early, every time
	//Packet 	 []byte			// packet constructor
}

type ScanSpec struct {
	Target   TargetSpec
	NetDeets NetSpec
}

// set up global constants for our port selection and use
const (
	adminPortRange uint   = 1024
	maxPorts       uint16 = 65535
)

func main() {
	var thisScan ScanSpec // TODO: newScanSpec constructor, returning *ScanSpec
	var wg sync.WaitGroup
	thisScan.Target.Addr = "127.0.0.1"                          // host/IP target. [NOTE: net.Dial() host must be IP]
	thisScan.NetDeets.Protocol = "tcp"                          // TCP/UDP/ICMP scan indicator
	thisScan.NetDeets.PortList = buildPortsList("tcp_test_win") // TEST LINE - remove after MVP #7
	for _, port := range thisScan.NetDeets.PortList {
		target := getTcpHostPortString(thisScan.Target.Addr, port)
		go tcpScan(target, &wg) // fire all scans off concurrently
		wg.Add(1)               // queue up one waitgroup per scan
	}
	wg.Wait() // wait for the returns to finish
}

func buildPortsList(sp string) []uint16 {

	var tTw = []uint16{135, 137, 139, 445, 623, 3389, 5040, 5985, 8000, 9999} // TEST functionality; windows hosts
	var tS = []uint16{20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 135, 137, 139, 143, 177, 179, 389, 443, 445, 464, 512, 513, 514, 515, 546, 547, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1270, 1337, 1433, 1434, 1521, 2222, 2323, 2375, 2483, 2484, 3306, 3333, 3389, 5060, 5061, 5432, 5800, 5900, 8008, 8080, 8081, 8088, 8443}
	var tE = []uint16{37, 49, 70, 82, 83, 85, 109, 115, 162, 201, 220, 264, 444, 464, 497, 530, 543, 544, 601, 631, 639, 666, 749, 750, 751, 752, 843, 902, 903, 992, 1080, 1194, 1514, 1701, 1723, 1741, 1812, 1813, 2049, 2082, 2083, 2095, 2096, 2100, 2376, 2638, 3128, 3268, 3269, 3689, 4333, 4444, 5000, 6514, 6881, 8000, 8089, 6000, 6001, 6665, 6666, 6667, 6668, 6669, 8333, 8334, 8888, 9001, 9333, 10000, 12345, 18080, 18081, 19132, 20000, 31337}
	var uS = []uint16{67, 68, 69, 123, 138, 161, 162, 264, 500, 514, 520, 521, 853, 902, 1433, 1434, 1812, 1813, 2049, 3268, 3269, 3260, 3478, 3479, 3480, 3481, 4500, 4567, 5000, 5001, 5060, 10000, 11371}

	switch sp {
	case "tcp_test_win":
		return tTw
	case "tcp_short":
		return tS
	case "tcp_extra":
		// make a slice able to hold 2 port arrays and enough head room for 32 more user-specified ports.
		// NOTE: Made with len() so we can edit the tS, tE, uS portlist definitions without having to remember to update the math
		tX := make([]uint16, len(tS)+len(tE), len(tS)+len(tE)+32)
		copy(tX, tS)
		tX = append(tX, tE...)
		return tX
	case "udp_short":
		return uS
	default:
		return []uint16{0} // zero is the error condition
	}
}

/*
tcpScan() takes a Dial target string [ipv4addr:portnum], scans that target, and adjust the waitgroup counter
*/
func tcpScan(t string, wg *sync.WaitGroup) {
	conn, err := net.Dial("tcp", t)
	fmt.Printf("tcpScan [%s] :: ", t)
	if err != nil {
		fmt.Printf("Error: [")
		fmt.Print(err)
		fmt.Printf("]\n")
	} else {
		fmt.Print("Success!\n")
		conn.Close()
	}
	wg.Done()
}

func getTcpHostPortString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}
