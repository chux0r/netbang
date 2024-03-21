package main
/******************************************************************************
* netBang 
*
* Go module: chux0r.org/netbang
* Github:    https://github.com/chux0r/netbang
* 
* Scrappy network scanner written in Go. Written to re-explore the idea of
* "scanning", whether old methods and assumptions remain valid, and how recon
* tools could or should evolve to remain valuable in the "new realm".
*
* Props to Fyodor =) Nmap is still and will likely remain, the boooooomb!
* In other words, netBang isn't meant to replace or dethrone anything. Just
* adding to a class of cool tools and methods I have used and loved.
*
* 14AUG2023
* CT Geigner ("chux0r")
*
* 12DEC2023 - Renamed to "netBang".
*
* What's being developed NOW-ish
* ------------------------------------------------------
* 1) Raw IP sockets AF_INET stuff+packet constructor next.
* 2) Silent recon stuff, OSINT, intel/data collection, API integrations
* 3) IPv6 integration
* 4) Target smarts
* Rationale:
* net.Dial() is pretty ok, but it abstracts lots of stuff. I'm stuck with a
* full-3-way TCP handshake, since there's no controlling the connection or the
* packet flags or anything like that.
* In short- it's too well behaved for what we need to do.
*
* Next features hit-list:
* ------------------------------------------------------
* Recon base + intel gathering using Shodan
* Improved error processing/context-adding/reporting
* Trap SIGINT(Ctrl-C), Stop scan and gather whatev report data exists
*
* Ideas! Fun to watch 'em rot in a pile. Amazing when I actually implement!
* =============================================================================
* Multicast fun
* BGP/OSPF fun
* IP history & "associations"
* ICMP scanning/host ping and other ICMP uses
* Hardware address/local network tomfoolery
* WHOIS data
* other interesting transport protocols nobody pays attention to? 
******************************************************************************/

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"net/netip"
)

// NetSpec defines networks, protocols, and details at layers  2, 3, and 4. 
// Port definitions included since TCP and UDP and ubiquitous.
// In many libraries, what I call "Protocol" is defined as "Network". See
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers for "ip:0xNN"- 
// form combinations.
type NetSpec struct {
	Protocol string       // arp, ppp, ip, ip4, ip6:icmp, ip:11, tcp, udp, etc
	PortList []uint16     // static ports list
	BangSpan []PortRange  // optional port range
}

type PortRange struct {
	Start uint16
	End   uint16
}

// Targets, nodes, our stuff, everything. This is how we describe them
// NOTE: supercedes "TargetSpec".
type Target struct {
	Obj     string         // Unevaluated address/object input. can be IPs, networks, hostnames, hostname:port, URL/URIs, MACs, hostname+protocol, whatever.  In practice, it is usually the <TARGET>, but can describe any object we wish.
	Hostn   string         // Hostname in "wah.blah.com" format. Can be just a domain name if DNS CNAME record is defined.
	Ip      net.IP         // []byte Using std library defs, no sense reinventing any of this
	Mask    net.IPMask     // []byte
	Port    uint16         // TCP or UDP portnumber
	Mac     net.HardwareAddr // layer 2; local net
	Lookups DnsData        // Name resolution, reverse lookups, DNS foo
}

// (*Target).Network() and (*Target).String() implement the net.Obj interface, used in PacketConn.WriteTo()
func (ts *Target) Network() string {
	return "ip4:tcp"
}

// (*Target).Network() and (*Target).String() implement the net.Obj interface, used in PacketConn.WriteTo()
func (ts *Target) String() string {
	return fmt.Sprint(ts.Ip.String(), ":", strconv.Itoa(int(ts.Port)))
}

// (*Target).EvalObj() evaluates input .Obj to determine what it is. IP (v4 or v6) address, or hostname. Sets (*Target).(stuff) if true.
// Returns code corresponding to results:
// 0	Unknown/error
// 1	IPv4 address
// 2	IPv6 address
// 3    Hostname
func (ts *Target) EvalObj() uint8 {
	// ipaddr?
	ip, err := netip.ParseAddr(ts.Obj)
	if err != nil {
		// not an IP address, continue
	} else {
		ts.Ip = ip.AsSlice() 
		l := len(ts.Ip)
		if l == 4 {
			return 1 // is IPv4 addr
		} else if l == 16 {
			return 2 // is IPv6 addr
		} else {
			log.Printf("IP detect/parse error. Error value input: [%v]\n",ts.Ip)
			return 0
		} 
	}
	err = ts.Lookups.resolve(ts.Obj)
	if err != nil {
		log.Printf("Resolution failure for name \"%s\": %s\n", ts.Obj, err.Error())
		return 0
	}
	ts.Hostn = ts.Obj
	fmt.Printf("\n[%s] resolves to:",ts.Obj)
	if len(ts.Lookups.IPs) > 1 { // returned multiple IPs
		for _, ip := range ts.Lookups.IPs {
			fmt.Printf("\n\t%s",ip)
		}
	} else {
		fmt.Printf("\n\t%s",ts.Lookups.IPs[0])
	}
	return 3
}

// Top-level domain, no dots, eg: "com", "edu", "org", etc.
func (ts *Target) TLD() string {
	if ts.Hostn == "" {
		return ""
	}
	t := strings.Split(ts.Hostn, ".")
	return t[len(t)-1]
}

type ScanSpec struct {
	Targ     Target
	NetDeets NetSpec
	Timeout  int32 //timeout in ms
}

var ThisScan ScanSpec
var Resolv DnsData
var BangMode uint8 = 1 // Modes: info: 0, scanning: 1, recon: 2

func init() {
	scanConstructor() // initialize our struct with reasonable default values

	// TODO: complete flags/options commented out below:
	//doDo       := flag.Bool("do", false, "Specify the activity: scan, qrecon, dnsinfo. Default is \"scan\".")
	envDo := flag.Bool("env", false, "Print environment, platform, and network details for your client endpoint.")
	//fakeDo     := flag.Bool("dryrun", false, "Do not execute. Print current activities list, pre-validate all, print config and pre-conditions.")
	helpDo := flag.Bool("h", false, "Pull up the detailed \"help\" screen.")
	helpDo2 := flag.Bool("help", false, "Same as \"-h\", above.")
	listsDo := flag.Bool("l", false, "Print all pre-configured TCP and UDP port group lists and list names. \n\t(--lists <Listname>) shows detailed port listing for <Listname>.")
	listsDo2 := flag.Bool("lists", false, "Same as \"-l\", above.")
	portsDo := flag.String("p", "", "Specify a port or ports, and/or named portlists to use in a comma-delimited list. TCP or UDP scans only.\n\t(Available port lists may be pulled up with \"netscanx --lists\")")
	portsDo2 := flag.String("ports", "", "Same as \"-p\", above.")
	portsfileDo := flag.String("pf", "", "Input comma-delimited list of target ports from a file.")
	portsfileDo2 := flag.String("portsfile", "", "Same as \"-p\", above.")
	protoDo := flag.Bool("proto", false, "Define the protocol to use: tcp, udp, or icmp. Default is \"tcp\".")
	reconDo := flag.String("recon", "", "\"The quietest scan? No scan at all.\"\n\t\t--chux0r\nList recon services and methods available with \"--recon list\" or specify service, method and any API keys needed.")
	dnsrvDo := flag.Bool("resolver", false, "Set DNS resolver to use. Default is to use your system's local resolver.")
	timeoutSet := flag.Int("t", 3000, "Network connect timeout to use, in milliseconds. To use network-defined timeout, set to -1. Default is 3000(ms)")
	/*
		verboseDo  := flag.Bool("v", false, "Verbose runtime output")
		verboseDo2 := flag.Bool("verbose", false, "Same as \"-v\", above. ")
		verboseDo3 := flag.Bool("vv", false, "Debug-level-verbosity runtime output. Obscenely verbose.")
		verboseDo4 := flag.Bool("debug", false, "Same as \"-vv\", above.")
	*/

	flag.Parse()
	if *envDo {
		BangMode = 0
		ifstat()
		os.Exit(0)
	}
	// HELP MENU
	if *helpDo || *helpDo2 || len(os.Args) <= 1 { //Launch help screen and exit
		BangMode = 0
		fmt.Print(
			`
USAGE:
netbang [--env]
	Print client network environment details.
netbang [-h|--help]
	Print this help screen.
netbang [-l|--lists] [<Listname>] 
	Print all usable pre-configured TCP and UDP port group lists and names. With <Listname>, show detailed port listing for <Listname>. 

netbang [[FLAGS] <object(,optionals)>] <TARGET>
	SCANNING FLAGS
		[-p|--ports] <num0(,num1,num2,...numN,numA-numZ,named_list)> 
		Specify port numbers, port ranges, and/or named portlists to use. TCP or UDP proto only. 
		(View named portlists with --lists)

		[-pf|--portsfile] <(directory path/)filename>
		Input from file a comma-delimited list of port numbers to scan. TCP or UDP proto only.

		[--proto] <tcp|udp>
		Specify protocol to use, tcp, udp, or icmp. Default is "tcp".

		[--resolver] <ipaddr> 
		DNS resolver to use. Default is to use your system's local resolver.

		[-t] <timeout, in ms>
		Network connect timeout to use. Defaults to 3 seconds (3000ms). To use network-defined timeout, set to -1.
	
	RECON FLAGS
		[--recon] <list> | [--recon] <service> <method> <apikey>
		Ninja recon module. List available modules with "list" or, specify a service, method, and optionally, API keys if needed. 

	<TARGET> 
		Object of scan. Target must be an IP address, an IP/CIDR range, or a valid hostname.
			
`)
		/* On tap, but not ready yet --ctg

		[--dryrun]
			Print activities list, pre-validate targets, print config and pre-conditions.
			Dry-run does NOT execute the scan.

		[-x|--exec] <scan(,tcpscan,udpscan,dnsinfo)>
			Specify activity(s): scan, tcpscan, udpscan, or dnsinfo. Default is "scan". */

		os.Exit(0)
	} else if *listsDo != false || *listsDo2 != false {
		BangMode = 0
		if flag.Arg(0) == "" {
			fmt.Print("\nPlaceholder for list available lists") // TODO: list lists func
		} else {
			fmt.Print("\nPlaceholder for per-list item printout") // TODO: list named list items func
		}
		os.Exit(0)
	}
	if len(*portsDo) > 0 || len(*portsDo2) > 0 || len(*portsfileDo) > 0 || len(*portsfileDo2) > 0 { // what if some crazy person sets all of these? Hm. Sure. Why not. Just detect it and append everything together with slicefu
		BangMode = 1
		ThisScan.NetDeets.PortList = []uint16{}      // clear the default port definitions since we GOIN'CUSTOM yee-haw
		if len(*portsDo) > 0 && len(*portsDo2) > 0 { //ifdef -p --ports
			log.Print("Warning: Ports given with both -p and --ports. Combining.")
		}
		if len(*portsfileDo) > 0 && len(*portsfileDo2) > 0 { // -pf --portsfile <filename>
			log.Print("Warning: Multiple input files given with both -pf and --portsfile. Combining.")
		}
		if len(*portsDo) > 0 { // ifdef -p
			doPortsFinal(*portsDo)
		}
		if len(*portsDo2) > 0 { // ifdef -ports
			doPortsFinal(*portsDo2)
		}
		if len(*portsfileDo) > 0 { // ifdef -pf read given user port config file
			log.Printf("Opening user-defined port config file [%s].", *portsfileDo)
			pconf, err := os.Open(*portsfileDo)
			p := make([]byte, 4096)
			if err != nil {
				log.Fatalf("Error opening file [%s]: [%s]. Exiting", *portsfileDo, err.Error())
			}
			defer pconf.Close()
			fsize, err := pconf.Read(p)
			if err != nil {
				log.Fatalf("Error reading file: [%s]. Exiting", *portsfileDo)
			}
			p = p[:fsize] // trim buffer to infile size or we'll have NUL padding everywhere, which will cause paresePortsCdl to misparse and barf
			fmt.Printf("\nData read from cf file: >> %s", string(p))
			doPortsFinal(string(p))
		}
	}

	if *protoDo {
		BangMode = 1
		if flag.Arg(0) == "" {
			fmt.Print("\nWarning: No protocol listed with --proto. Using \"tcp\".")
		} else {
			ThisScan.NetDeets.Protocol = strings.ToLower(flag.Arg(0))
			if ThisScan.NetDeets.Protocol != "tcp" && ThisScan.NetDeets.Protocol != "udp" { 
				log.Fatalf("Error: Invalid protocol: %s! Allowed protocols are \"tcp\" or \"udp\".", flag.Arg(0)) // MOVE THESE PROTO CHECKS OUT TO RESPECTIVE MODULES (there will be more protocols allowed, and better contextual ways to validate, but it won't be here --ctg)
			}
		}
	}
	//[--recon] <list> | <shodan> <method> <apikey>
	if len(*reconDo) > 0 {
		
		
		/* TEST //
			for i := 0; i < flag.NArg(); i++ {
				fmt.Printf("\n\tTEST: Shodan call, arg [%d]: val [%s]", i, flag.Arg(i))
			}
			fmt.Printf("\n\tTarget val: [%s]\n", os.Args[len(os.Args)-1])
		// TEST */
		
		
		BangMode = 2		
		ThisScan.Targ.Obj = os.Args[len(os.Args)-1]         // last arg should always be the target
		if *reconDo == "list" {
			fmt.Print("\nNinja recon services and methods available:")
			for _, m := range Rmethods {
				fmt.Printf("\n\t%s\n", m)
			}
			os.Exit(0)
		} else if *reconDo == "shodan" {
			ThisScan.Targ.Ip = net.ParseIP(ThisScan.Targ.Obj) // valid IP given?
			if ThisScan.Targ.Ip == nil {
				log.Fatalf("For method %s, %s is not a valid target IP address.", flag.Arg(0), ThisScan.Targ.Obj)
			}
			shodn("hostip", flag.Arg(0), ThisScan.Targ.Ip.String())
			os.Exit(0)
		} else if *reconDo == "dns" {
			ThisScan.Targ.Lookups.resolve(ThisScan.Targ.Obj)	
			os.Exit(0)
		} else {
			log.Fatalf("Illegal recon service: [%s]", *reconDo)
		}
	}
	/*
		if *doDo {
			if flag.Arg(0) == "" {
				fmt.Print("Error: You must specify which netscanx activity to do after \"--do\" (tcpscan, udpscan, dnsinfo). Default is tcpscan.")
				os.Exit(1)
			}
		}
	*/
	if *dnsrvDo {
		if flag.Arg(0) == "" {
			log.Print("Warning: No DNS server IP specified with \"--resolver\". Using default.")
		} else {
			setCustomResolver(&Resolv.Dns, flag.Arg(0)) // pass it our DnsInfo struct to populate/use
		}
	}
	ThisScan.Timeout = int32(*timeoutSet)
	ThisScan.Targ.Obj = os.Args[len(os.Args)-1] // last arg will always be the target hostname/addr
}

func main() {
	ifstat()
	if BangMode == 1 {
		bangHost(ThisScan.NetDeets.PortList, ThisScan.Targ.Obj, ThisScan.NetDeets.Protocol)
	}
}

/* scanConstructor() just start off with sensible default values. Most defaults aim at "tcp scan" context */
func scanConstructor() {
	ThisScan.NetDeets.Protocol = "tcp"
	ThisScan.NetDeets.PortList = buildNamedPortsList("tcp_short")
	ThisScan.Targ.Ip = net.IP{127,0,0,1}
	ThisScan.Targ.Obj = ThisScan.Targ.Ip.String()
}

/******************************************************************************
bangHost()

Bangscan one host - For proto (tcp/udp) all ports given, scan single host and
format results

	INPUT: 	[]uint16 port list (can be empty)
			protocol, TCP or UDP
			target hostname or IP
	PROCESSING
			Launches concurrent port scans at a target host
			Catches results strings via IPC channel receiver.
	OUTPUT
			Scan results data/report
******************************************************************************/
func bangHost(pl []uint16, host string, proto string) {

	prtot := 0 //port range total ports represented
	for _, pspan := range ThisScan.NetDeets.BangSpan {
		prtot += pspan.Size() //add up size of all defined/given port ranges
	}
	jobtot := len(pl) + prtot // number of scan jobs equal to portlist total plus portranges total
	scanReport := make([]string, 0, jobtot)
	scanIpc := make(chan string) // com pipe: raw, unordered host:port try response data or errors
	rxc := 0
	job := 0
	if len(pl) <= 0 { // if no ports specified, use short default common ports
		if proto == "tcp" {
			pl = buildNamedPortsList("tcp_short")
		} else if proto == "udp" {
			pl = buildNamedPortsList("udp_short")
		} else {
			log.Fatalf("Error: Invalid protocol: [%s]! Allowed protocols are \"tcp\" or \"udp\".", proto)
		}
	}
	fmt.Printf("\nBang target: [%s], Portcount: [%d]\n=====================================================", host, jobtot)
	// scan static port defs
	for _, port := range pl { // For all ports given, bang each one and report results
		sock := getSocketString(host, port)
		if proto == "tcp" {
			go bangTcpPort(sock, scanIpc, &job) // Bang bang! Single host:port per call
		} else if proto == "udp" {
			go bangUdpPort(sock, scanIpc, &job)
		} else {
			log.Fatalf("Error: Invalid protocol: [%s]! Allowed protocols are \"tcp\" or \"udp\".", proto)
		}
	}
	// if we have any, scan port ranges given
	if prtot > 0 {
		for _, spanDef := range ThisScan.NetDeets.BangSpan {
			for j := spanDef.Start; j <= spanDef.End; j++ {
				sock := getSocketString(host, j)
				if proto == "tcp" {
					go bangTcpPort(sock, scanIpc, &job) // Bang bang! Single host:port per call
				} else if proto == "udp" {
					go bangUdpPort(sock, scanIpc, &job)
				} else {
					log.Fatalf("Error: Invalid protocol: [%s]! Allowed protocols are \"tcp\" or \"udp\".", proto)
				}
			}
		}
	}
	fmt.Printf("\n%s portbangers unleashed...", strings.ToUpper(proto))

	// Channel receiver :: Get all concurrent scan job output and report
	for i := 0; i < jobtot; i++ {
		//for log := range scanIpc {
		log := <-scanIpc
		rxc++
		scanReport = append(scanReport, log)
	}
	fmt.Printf("\nJobs run: %d", job) //TEST
	//fmt.Printf("\nRecv'd job logs: %d.", rxc) //TEST
	close(scanIpc)
	printReport(scanReport)
}

/******************************************************************************
bangTcpPort()

	--:: [BANG, AS IN .:|BANG|:. *FUCKIN NOISY*] ::--
		Full 3-way TCP handshake
		net.Dial seems to like retrying [SYN->] sometimes (!) after getting [<-RST,ACK] lol

	Hits given target:port and records response.
	Shoots results back through IPC channel.
******************************************************************************/
func bangTcpPort(t string, ch chan string, job *int) {
	*job++
	joblog := fmt.Sprintf("[%s] -->\t", t)
	if ThisScan.Timeout < 0 { // timeout set to -1, use default host/network timeout
		conn, err := net.Dial("tcp", t)
		if err != nil {
			fmt.Printf("💀")
			ch <- fmt.Sprint(joblog, "[💀] ERROR: ", err.Error())
			//fmt.Printf("\n[%s]: Connection error: %s", t, err.Error())
		} else {
			defer conn.Close()
			fmt.Print("😎")
			ch <- fmt.Sprint(joblog, "[😎] OPEN")
			//fmt.Printf("\n[%s]: Connected ok: open", t)
		}
	} else {
		conn, err := net.DialTimeout("tcp", t, time.Duration(ThisScan.Timeout)*time.Millisecond) // net.Dial, but with configurable timeout so we can boogey when needed
		if err != nil {
			fmt.Printf("💀")
			ch <- fmt.Sprint(joblog, "[💀] ERROR: ", err.Error())
			//fmt.Printf("\n[%s]: Connection error: %s", t, err.Error())
		} else {
			defer conn.Close()
			fmt.Print("😎")
			ch <- fmt.Sprint(joblog, "[😎] OPEN")
			//fmt.Printf("\n[%s]: Connected ok: open", t)
		}
	}
}

/******************************************************************************
bangUdpPort()

	What. Isup. With Datagrams, amirite?
	Hits given UDP target:port and records response.
	Shoots results back through IPC channel.
******************************************************************************/
func bangUdpPort(t string, ch chan string, job *int) {
	rcvbuf := make([]byte, 1024)
	*job++
	joblog := fmt.Sprintf("[%s] -->\t", t)
	udpaddr, err := net.ResolveUDPAddr("udp", t)
	conn, err := net.DialUDP("udp", nil, udpaddr) // TODO: add default max time wait to this + Make configurable
	if err != nil {
		fmt.Printf("💀")
		ch <- fmt.Sprint(joblog, "[💀] ERROR: ", err.Error())
		//fmt.Printf("\n[%s]: Connection error: %s", t, err.Error())
	} else {
		defer conn.Close()
		_, err = conn.Write([]byte("loludp"))
		if err != nil {
			fmt.Printf("💀")
			ch <- fmt.Sprint(joblog, "[💀] ERROR: ", err.Error())
		} else {
			_, err = conn.Read(rcvbuf)
			if err != nil {
				fmt.Printf("💀")
				ch <- fmt.Sprint(joblog, "[💀] ERROR: ", err.Error())
			} else {
				fmt.Print("😎")
				ch <- fmt.Sprint(joblog, "[😎] OPEN")
			}
		}
	}
}

func printReport(ss []string) {
	fmt.Printf("\n%s Scan Results\n================================================================================", ThisScan.Targ.Obj)
	for _, result := range ss {
		fmt.Printf("\n%s", result)
	}
	fmt.Print("\n")
}
