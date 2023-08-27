/******************************************************************************
* netscanx
* (net-SKANKZ)
*
* Scrappy network scanner written in Go, mostly to answer what boost Go
* concurrency gives. Also, fun to see how far I can get network-features-wise.
*
* Props to Fyodor =) Nmap is still and will likely remain, the boooooomb ;)
* In other words, this isn't supposed to replace or unthrone anything; maybe
* just add to a class of cool tools I have used and love.
*
* Making this up as I go, by whatever entertains me most >8]
*
* 14AUG2023
* CT Geigner ("chux0r")
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
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type NetSpec struct {
	Protocol string   // "tcp" - expand into "ProtoSpec" later to accommodate UDP, ICMP/Type/Subtype
	PortList []uint16 // all der portz
	//Flags    net.Flags		// xmas comes early, every time; (impl. syscall.RawConn)
	//Packet 	 []byte			// packet constructor
}

type DnsData struct {
	Dns      net.Resolver // DNS fun, but mostly lookups/resolution
	Addrs    []string     // IPs resolved
	RevNames []string     // IP reverse-lookup names
}

type TargetSpec struct {
	Addr    string // names or IPs in string fmt == we should use net.Addr.String() for each element
	Ip      net.IP // []byte, it's the methods we want, really
	isIp    bool
	isHostn bool
	//Mac  net.HardwareAddr // layer 2; local net
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

var thisScan ScanSpec // TODO: newScanSpec constructor, returning *ScanSpec

func init() {

	// TODO: complete flags/options commented out below:
	helpDo := flag.Bool("help", false, "Pull up a \"help\" menu.")
	//fakeDo := flag.Bool("dryrun", false, "Do not execute. Print current activities list, pre-validate all, print config and pre-conditions.")
	portsDo := flag.Bool("ports", false, "Define single ports, a comma-delimited port list, and/or a named portlist.")
	//protoDo := flag.String("proto", "tcp", "Define the protocol to use: tcp, udp, or icmp. Default is \"tcp\".")
	//doDo := flag.String("do", "scan", "Specify the activity: scan, tcpscan, udpscan, dnsinfo. Default is \"scan\".")
	//dnsrvDo := flag.String("resolver", "", "Set the DNS resolver IP to use. Default is your system's defined resolver")
	listsDo := flag.Bool("lists", false, "Print listnames available. If listname specified (--lists <listname>), print that list's contents.")
	flag.Parse()

	if *helpDo || len(os.Args) <= 1 { //Launch help screen and exit
		fmt.Print(
			`
USAGE:
netscanx [-h|--help] :: Print this help screen
netscanx [-l|--list] [<Listname>] :: Print all named port lists. With <Listname>, show all items in named list.

netscanx [[FLAGS] <object(,optionals)>] <target>
	FLAGS:
	[-x|--exec] <scan(,tcpscan,udpscan,dnsinfo)> :: Specify activity(s): scan, 
		tcpscan, udpscan, or dnsinfo. Default is "scan".
	
	[--ports] <num0(,num1,num2,...numN,named_list)> :: Specify port, ports, and/
		or named portlists to use. (Portlists listed in --lists)
	
	[--proto] <protocol> :: Specify protocol to be used. Default is "tcp".
	
	[--dryrun] :: Print activities list, pre-validate targets, print config and
		pre-conditions. Dry-run does NOT execute the scan.
	
	[--resolver] <ipaddr> Set new DNS resolver IP. Default is to use your 
		system's local resolver.

	<target>: 
	Target must be an IP address, an IP/CIDR range, or a valid hostname

`)
		os.Exit(0)
	} else if *listsDo != false {
		if flag.Arg(0) == "" {
			fmt.Print("Placeholder for list available lists\n") // TODO: list lists func
		} else {
			fmt.Print("Placeholder for per-list item printout\n") // TODO: list named list items func
		}
		os.Exit(0)
	}
	//if protoDo {}
	if *portsDo {
		if flag.Arg(0) == "" {
			fmt.Print("Error: You must list ports to use after \"--ports\".")
			os.Exit(1)
		} else {
			pargs := flag.Arg(0)                                        // gather user-spec'd ports
			p, pl := parsePortsCdl(pargs)                               // TODO: create func that assembles final []uint16 port list from spec
			fmt.Println("Ports specified: ", p, "List specified: ", pl) // TEST/TODO: remove when port assembler complete
		}
	}
	// TARGET VALIDATION CODE GOES HERE
	thisScan.Target.Addr = os.Args[len(os.Args)-1] // last arg should always be always the target hostname/addr
	/* // TEST OUTPUT
	fmt.Printf("Number of Args is %d\n", len(os.Args))
	for i, arg := range os.Args {
		fmt.Printf("\nArg%d: %s\n", i, arg)
	}
	fmt.Println("helpDo has value ", *helpDo)
	fmt.Println("fakeDo has value ", *fakeDo)
	fmt.Println("portsDo has value ", *portsDo)
	fmt.Println("protoDo has value ", *protoDo)
	fmt.Println("doDo has value ", *doDo)
	fmt.Println("dnsrvDo has value ", *dnsrvDo) */
}

func main() {

	var wg sync.WaitGroup // set up wait group for concurrent scanning

	// thisScan.Target.Addr = "127.0.0.1"                          // host/IP target. [NOTE: net.Dial() host must be IP]
	thisScan.NetDeets.Protocol = "tcp"                          // TCP/UDP/ICMP scan indicator TODO: move this defaut to the constructor() func
	thisScan.NetDeets.PortList = buildPortsList("tcp_test_win") // TEST LINE - TODO: remove after MVP #7 --ports check

	// TCP scan :: invoke section [TODO:MODULE->MOVE]
	for _, port := range thisScan.NetDeets.PortList {
		target := getHostPortString(thisScan.Target.Addr, port)
		go tcpScan(target, &wg) // fire all scans off concurrently
		wg.Add(1)               // queue up one waitgroup per scan
	}
	wg.Wait() // wait for the returns to finish
	// TCP scan done

	// DNS Lookup :: invoke section [TODO:MODULE->MOVE]
	// thisScan.Target.Addr = "megaohm.net" // TEST NAME REM before v.1
	t := net.ParseIP(thisScan.Target.Addr) // Answers: is target a FQDN or an IP?
	var Resolv DnsData
	ctx := context.Background() // TEST/TODO: determine which context would be most helpful in a DNS lookup. Using Background() for now
	if t != nil {               // if Target is an IP
		thisScan.Target.Ip = []byte(thisScan.Target.Addr)
		thisScan.Target.isIp = true
	} else { // if Target is a hostname/FQDN
		thisScan.Target.isHostn = true
		fmt.Printf("DNS Lookup for %s: \n", thisScan.Target.Addr)

		addrs, err := Resolv.Dns.LookupHost(ctx, thisScan.Target.Addr)
		if err != nil {
			fmt.Printf("Error: [")
			fmt.Print(err)
			fmt.Printf("]\n")
		} else {
			for i, addr := range addrs {
				fmt.Printf("\tIP #%d: %s\n", i+1, addr)
			}
		}
		fmt.Printf("(DNS lookup complete)\n")
	}

	fmt.Printf("Now, with custom resolver def: [8.8.8.8:53]\n")
	setCustomResolver(&Resolv.Dns, "8.8.8.8") // TODO: convert to user-configurable
	addrs, err := Resolv.Dns.LookupHost(ctx, thisScan.Target.Addr)
	if err != nil {
		fmt.Printf("Error: [")
		fmt.Print(err)
		fmt.Printf("]\n")
	} else {
		for i, addr := range addrs {
			fmt.Printf("\tIP #%d: %s\n", i+1, addr)
		}
	}
	fmt.Printf("(DNS lookup complete)\n")
	// END DNS Lookup section
}

/* buildPortsList() returns a slice of uint16 port numbers useful for TCP and UDP scanning */
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

/* tcpScan() takes a Dial target string [ipv4addr:portnum], scans that target, and adjusts the waitgroup counter */
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

/* getHostPortString() returns a "host:port" target string usable by net.Dial() */
func getHostPortString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}

/* setCustomResolver lets user set a custom DNS host, by IP. Port 53 is assumed. */
func setCustomResolver(dns *net.Resolver, ip string) {
	dnsHost := getHostPortString(ip, uint16(53)) // TODO :: validate given IP
	dns.PreferGo = true
	dns.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * time.Duration(5), // FUTURE CONSIDERATION: Set custom timeout?
		}
		return d.DialContext(ctx, network, dnsHost) // TEST 8.8.8.8:53 as dnsHost
	}
}

/*
parsePortsCdl() parses the comma-delimited string passed in by the user, using
the --ports flag. Since the user can specify either numbers or port list names,
the func must detect item type 1st, then perform validation. In the case of
port numbers, since we bring everything as string data, there is some fun
converting runes. Returns ports as []uint16, any named port lists as []string.
*/
func parsePortsCdl(s string) ([]uint16, []string) {
	var r1 []string
	var r2 []uint16
	fmt.Println("ParsePortsCDL input string: ", s)
	list := strings.Split(s, ",")
	for _, item := range list { // Eval each list item
		item = strings.TrimSpace(item) // be nice and trim it up, just in case
		fmt.Println("\nItem:", item)   //TEST
		num := false
		var tot int32 = 0
		itlen := len([]rune(item))
		for i := itlen - 1; i >= 0; i-- { // walk the chars
			char := item[i]
			if (int32(char)-48 < 0) || (int32(char)-48) > 9 { // if char is not 0-9
				num = false
				break // if NaN, break out
			} else { // Numeric; convert and calc
				num = true
				var mlt int32 = 1                         // multiplier, to rebuild our port num piece by piece``
				fmt.Printf("\nNum character is %c", char) // TEST
				if char != '0' {                          // only when we have a non zero num to compute
					digit := itlen - 1 - i // len-1-i is most signif. digit L->R
					//if digit > 0 {
					for j := digit; j > 0; j-- { // computationally less expensive than using math.Pow10 and float64s :)
						mlt = mlt * 10
					}
					//}
					fmt.Printf(" times %d (x10^%d)", mlt, digit)
					tot = tot + (int32(char)-48)*mlt
					fmt.Printf(", totaling %d", tot)
				}
			}
		}
		if num == false { // put the name in the list of names
			r1 = append(r1, item)
		} else { // put the port in the list of ports
			r2 = append(r2, uint16(tot))
		}
	}
	fmt.Println("Strings slice: ", r1) // TEST
	fmt.Print("uint16 slice: ", r2)    // TEST
	return r2, r1
}
