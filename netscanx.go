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
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
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
var Resolv DnsData

func init() {
	scanConstructor() // initialize our struct with reasonable default values

	// TODO: complete flags/options commented out below:
	helpDo := flag.Bool("help", false, "Pull up a \"help\" menu.")
	//fakeDo := flag.Bool("dryrun", false, "Do not execute. Print current activities list, pre-validate all, print config and pre-conditions.")
	portsDo := flag.Bool("ports", false, "Define single ports, a comma-delimited port list, and/or a named portlist.")
	//protoDo := flag.Bool("proto", false, "Define the protocol to use: tcp, udp, or icmp. Default is \"tcp\".")
	//doDo := flag.Bool("do", false, "Specify the activity: scan, tcpscan, udpscan, dnsinfo. Default is \"scan\".")
	dnsrvDo := flag.Bool("resolver", false, "Set the DNS resolver IP to use. Default is your system's defined resolver")
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
	
	[--resolver] <ipaddr> DNS resolver to use. Default is to use your system's 
		local resolver.

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
			thisScan.NetDeets.PortList = []uint16{}                     // clear the defaults
			pargs := flag.Arg(0)                                        // gather user-spec'd ports
			p, pl := parsePortsCdl(pargs)                               // TODO: create func that assembles final []uint16 port list from spec
			fmt.Println("Ports specified: ", p, "List specified: ", pl) // TEST/TODO: remove when port assembler complete
			if len(pl) > 0 {                                            // if we have named lists...
				for i := 0; i < len(pl); i++ {
					// resize the portlist appropriately and reassemble
					ts1 := thisScan.NetDeets.PortList
					ts2 := buildNamedPortsList(pl[i])
					thisScan.NetDeets.PortList = make([]uint16, len(ts1)+len(ts2), len(ts1)+len(ts2)+32)
					copy(thisScan.NetDeets.PortList, ts1)
					thisScan.NetDeets.PortList = append(thisScan.NetDeets.PortList, ts2...)
				}
			}
			if len(p) > 0 {
				for _, ptmp := range p {
					thisScan.NetDeets.PortList = append(thisScan.NetDeets.PortList, ptmp)
				}
			}
		}
	}
	/*if *doDo {
		if flag.Arg(0) == "" {
			fmt.Print("Error: You must specify which netscanx activity to do after \"--do\" (tcpscan, udpscan, dnsinfo). Default is tcpscan.")
			os.Exit(1)
	}*/
	if *dnsrvDo {
		if flag.Arg(0) == "" {
			fmt.Print("Error: You must specify the IP of a DNS server to use with \"--resolver\".")
			os.Exit(1)
		} else {
			setCustomResolver(&Resolv.Dns, flag.Arg(0)) // pass it our DnsInfo struct to populate/use
		}
	}
	// TODO: TARGET VALIDATION CODE GOES HERE
	thisScan.Target.Addr = os.Args[len(os.Args)-1] // last arg should always be always the target hostname/addr
}

func main() {

	var wg sync.WaitGroup // set up wait group for concurrent scanning

	// thisScan.Target.Addr = "127.0.0.1"                          // host/IP target. [NOTE: net.Dial() host must be IP]
	if len(thisScan.NetDeets.PortList) <= 0 { // if no ports specified, set the default port list
		thisScan.NetDeets.PortList = buildNamedPortsList("tcp_short")
	}
	// TCP scan :: invoke section [TODO:MODULE->MOVE]
	for _, port := range thisScan.NetDeets.PortList {
		// need IP target-verify here and resolve name call if fail
		target := getHostPortString(thisScan.Target.Addr, port) // TODO: Target Addr needs to be ip, use Target.IP instead
		go tcpScan(target, &wg)                                 // fire all scans off concurrently
		wg.Add(1)                                               // queue up one waitgroup per scan
	}
	wg.Wait() // wait for the returns to finish
	// TCP scan done
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
