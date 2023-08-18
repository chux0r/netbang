/******************************************************************************
* netscan-x
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
* "Do want" features hit-list:
* ------------------------------------------------------
* UDP scanning (DialUDP)
* more integration using stdlib net structures and interfaces
* ICMP host ping and other ICMP uses
* Hardware address/local network tomfoolery
* Multicast fun
* BGP fun
* DNS fun
* SSL cert harvesting, eval, and validation
*
******************************************************************************/
package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
	//	"os"
	//	"flag"
)

type ProtoSpec struct {
	Name    string   // TCP, UDP (and ICMP, eventually) == we should use interface net.Addr.Network() for this (same idea/both string type)
	Type    uint8    // ICMP only, see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
	Subtype []string // ICMP only, see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-ext-classes
}

type TargetSpec struct {
	Addr     []string         // names or IPs in string fmt == we should use net.Addr.String() for each element
	Ip       net.IP           // []byte, it's the methods we want, really
	Mac      net.HardwareAddr // good inclusion for local scanning
	Hostname bool             // is/not hostname
	Ipv4     bool             // is/not ipv4
	Ipv6     bool             // is/not ipv6
}

type NetSpec struct {
	Protocol ProtoSpec
	Addr     []string
	PortList []uint16
	Flags    net.Flags
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
	var sel rune
	var thisScan ScanSpec
	valid := true
	comchan := make(chan string) // channel for all concurrent scan+result i/o buffering+brokering
	// the unique per-job worker string (chan string) here is the "host:port"
	// string given to Dial(); a.k.a "target", "targ", and "t"

	// NOTE UI/user input needs to be in its own func eventually --ctg
	// FLAGS :: this ui should only show when netscan-x is launched with "--interactive" (otherwise it's annoying and not flexible/scriptable)
	thisScan.NetDeets.Protocol.Name = "tcp"
	fmt.Scanf("\n\tEnter hostname or IP to scan: %s", thisScan.Target.Addr[0])
	for valid {
		fmt.Scanf("\nSelect one:\n\tA] TCP services scan, most common ports.\n\tB] TCP scan, extended ports list.\n\tC] TCP scan, ~1K admin ports only.\n\tD] TCP scan, exhaustive (~65K ports). \n\tE] UDP scan, common ports.\n\tF] Single host and port.\n\n\tSelect ->  %s", &sel)
		sel = unicode.ToUpper(sel)
		//Build the detailed ScanSpec object we'll pass to ScanIt()
		switch sel {
		case 'A': // TCP single host, scan only most common ports

			thisScan.NetDeets.PortList = buildScanPortsList("tcp_short")
			for _, port := range thisScan.NetDeets.PortList {
				target := assembleHostPortString(thisScan.Target.Addr[0], port)
				scanTcp(target, comchan)
			}
		case 'B': // TCP single host, scan common ports plus bigger list of ports we'd want to know about
			thisScan.NetDeets.PortList = buildScanPortsList("tcp_extra")
			for _, port := range thisScan.NetDeets.PortList {
				target := assembleHostPortString(thisScan.Target.Addr[0], port)
				scanTcp(target, comchan)
			}
		case 'C': // TCP admin ports
			for i := 0; i < int(adminPortRange); i++ {
				target := assembleHostPortString(thisScan.Target.Addr[0], uint16(i))
				scanTcp(target, comchan)
			}
		case 'D': // TCP all ports
			for i := 0; i < int(maxPorts); i++ {
				target := assembleHostPortString(thisScan.Target.Addr[0], uint16(i))
				scanTcp(target, comchan)
			}
		case 'E': // UDP single host, portlist "udp_short"
			thisScan.NetDeets.Protocol.Name = "udp"
			thisScan.NetDeets.PortList = buildScanPortsList("udp_short")
			for _, port := range thisScan.NetDeets.PortList {
				target := assembleHostPortString(thisScan.Target.Addr[0], port)
				scanTcp(target, comchan)
			}
		case 'F': // single host and port
			fmt.Scanf("\n\tEnter port to scan: %s", thisScan.NetDeets.PortList[0])
			for {
				fmt.Scanf("\n\tWhat protocol? (TCP or UDP): %s", &thisScan.NetDeets.Protocol.Name)
				thisScan.NetDeets.Protocol.Name = strings.ToLower(thisScan.NetDeets.Protocol.Name)
				if thisScan.NetDeets.Protocol.Name == "tcp" || thisScan.NetDeets.Protocol.Name == "udp" {
					break // it's good! Break outta this fresh hell.
				} else {
					fmt.Printf("\n\tError! \"%s\" is an invalid protocol selection.", thisScan.NetDeets.Protocol.Name)
				}
			}
		default:
			fmt.Printf("\n\tError! \"%c\" is an invalid menu selection.", sel)
			valid = false
		}
	}
	// Scans awaaaaaaaay.......
	for _, port := range thisScan.NetDeets.PortList {
		target := assembleHostPortString(thisScan.Target.Addr[0], port)
		scanTcp(target, comchan)
	}

	// Go, go, gadget AIR TRAFFIC CONTROL
	for targ := range comchan {
		go func(t string) {
			time.Sleep(500 * time.Millisecond) //<-- call Sleep() so it doesn't block in main()
			scanTcp(t, comchan)
		}(targ) //<- FUNCTION LITERAL: remember to call it after you define it, using "()"
	}
}

func scanTcp(target string, c chan string) {

	net.Dial("tcp", target)
	c <- target // let the channel broker know we're done
	return
	// When adding "fast" scanning, use "DialTimeOut", which allows us to set max time for name resolution, TCP connect
	//
	// func DialTimeout(network, address string, timeout time.Duration) (Conn, error)
	// DialTimeout acts like Dial but takes a timeout.
}

/*
func scanUdp(target string, c chan string) {
	net.DialUDP(proto, target,,) // ran into probs with UDP, will address later as TCP scanning is the 99% here
	fmt.Printf("\n\tUDP scanning normally happens here!")
}
*/

func assembleHostPortString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}

func buildScanPortsList(sp string) []uint16 {

	var tS = []uint16{20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 135, 137, 139, 143, 177, 179, 389, 443, 445, 464, 512, 513, 514, 515, 546, 547, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1270, 1337, 1433, 1434, 1521, 2222, 2323, 2375, 2483, 2484, 3306, 3333, 3389, 5060, 5061, 5432, 5800, 5900, 8008, 8080, 8081, 8088, 8443}
	var tE = []uint16{37, 49, 70, 82, 83, 85, 109, 115, 162, 201, 220, 264, 444, 464, 497, 530, 543, 544, 601, 631, 639, 666, 749, 750, 751, 752, 843, 902, 903, 992, 1080, 1194, 1514, 1701, 1723, 1741, 1812, 1813, 2049, 2082, 2083, 2095, 2096, 2100, 2376, 2638, 3128, 3268, 3269, 3689, 4333, 4444, 5000, 6514, 6881, 8000, 8089, 6000, 6001, 6665, 6666, 6667, 6668, 6669, 8333, 8334, 8888, 9001, 9333, 10000, 12345, 18080, 18081, 19132, 20000, 31337}
	var uS = []uint16{67, 68, 69, 123, 138, 161, 162, 264, 500, 514, 520, 521, 853, 902, 1433, 1434, 1812, 1813, 2049, 3268, 3269, 3260, 3478, 3479, 3480, 3481, 4500, 4567, 5000, 5001, 5060, 10000, 11371}

	switch sp {
	case "tcp_short":
		return tS
	case "tcp_extra":
		// make a slice able to hold the 2 uint16 TCP port arrays, with enough head room for 32 more user-specified ports.
		// NOTE: Made with len() so we can edit the tS, tE, uS portlist definitions without having to remember to update the math
		tX := make([]uint16, len(tS)+len(tE), len(tS)+len(tE)+32)
		tX = append(tX, tS...) // q: does the "..." variadic mess up our intentional len+32? Maybe I should use "copy" instead...
		tX = append(tX, tE...)
		return tX
	case "udp_short":
		return uS
	default:
		return []uint16{0} // zero is the error condition
	}

}

/*
// Specific-target-mode: Get a list of target hosts and ports
// Scanner mode: Get an IP range and a port or port-raneg to target

// get port availability

func init() {

	for _, arg := range os.Args {
		switch arg {
		case "t":
			fallthrough
		case "target":

			hostn := flag.String("host", "localhost", "Canonical name of host to scan.")
			portn := flag.String("p", "80", "TCP port number of service to scan")
			helpFlag := flag.String("h", "", "Show the netscan-x syntax help")
		}
	}
}
*/

/* ICMP ping reference code:

package main

import (
    "log"
    "net"
    "os"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

const targetIP = "8.8.8.8"

func main() {
    c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        log.Fatalf("listen err, %s", err)
    }
    defer c.Close()

    wm := icmp.Message{
        Type: ipv4.ICMPTypeEcho, Code: 0,
        Body: &icmp.Echo{
            ID: os.Getpid() & 0xffff, Seq: 1,
            Data: []byte("HELLO-R-U-THERE"),
        },
    }
    wb, err := wm.Marshal(nil)
    if err != nil {
        log.Fatal(err)
    }
    if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
        log.Fatalf("WriteTo err, %s", err)
    }

    rb := make([]byte, 1500)
    n, peer, err := c.ReadFrom(rb)
    if err != nil {
        log.Fatal(err)
    }
    rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
    if err != nil {
        log.Fatal(err)
    }
    switch rm.Type {
    case ipv4.ICMPTypeEchoReply:
        log.Printf("got reflection from %v", peer)
    default:
        log.Printf("got %+v; want echo reply", rm)
    }
}
*/
