package portfu

/******************************************************************************
* portfu.go :: chux0r.org/portfu
*
* Functions used by netBang specifically to support smart and quick port
* define, parse, selection, combination, and teeing up for TCP and UDP scans
*
* 	"a UDP bar walks into A packet...
* 	The bartender says, 'What'll you have buddy?'
* 	A regular at the bar corner looks up and sneers, 'Don't even waste ye time!
* 	He's never ordered.'"
*
* CT Geigner ("chux0r")
* 21 SEPT 2023
*
* 26 MAR 2024 Update :: Converted to chux0r.org/portfu; For local include
*
******************************************************************************/

import (
	"fmt"
	"log"
	"strings"

	"chux0r.org/uglynum"
)

const (
	AdminPortRange uint   = 1024
	MaxPorts       uint16 = 65535
)

/******************************************************************************
type PortList []uint16 

Useful for lots of TCP/UDP netNamg stuff. Methods to populate and manage.
******************************************************************************/
type PortList []uint16 

func (pl *PortList)Add(a []uint16) {
	//holdr := *pl
	
	fmt.Println("DEBUG: PortList pl[", pl, "] *pl[", []uint16(*pl), "] &pl[", &pl,"]")
	fmt.Println("DEBUG: The ports to ADD: [", a, "]")
	//fmt.Println("DEBUG: The COPY: holdr[", holdr, "] &holdr[", &holdr,"]")
	//*pl = make([]uint16, 0, len(holdr)+len(a)) //stretch capacity out to total size
	*pl = append(*pl, a...)	
	//fmt.Println("DEBUG: LEN holdr [", len(holdr), "] + LEN a [", len(a), "]")
	//fmt.Println("DEBUG: NEWLEN *pl [", len(*pl), "]")
	//fmt.Println("DEBUG: After MAKENEW: pl[", pl, "] *pl[", []uint16(*pl), "] &pl[", &pl,"]")
	//copy(*pl, holdr)
	fmt.Println("DEBUG: After COPY tmp INTO: pl[", pl, "] *pl[", []uint16(*pl), "] &pl[", &pl,"]")
	
	fmt.Println("DEBUG: After APPEND NEW PORTS pl[", pl, "] *pl[", []uint16(*pl), "] &pl[", &pl,"]")
	/*
	tmp := pl
	fmt.Println("DEBUG: PortList pl[", pl, "] *pl[", *pl, "] &pl[", &pl,"]")
	fmt.Println("DEBUG: The ports to ADD: [", a, "]")
	fmt.Println("DEBUG: The COPY tmp[", tmp, "] *pl[", *tmp, "] &pl[", &tmp,"]")
	*pl = make([]uint16, 0, len(*tmp)+len(a)) //stretch capacity out to total size
	fmt.Println("DEBUG: LEN tmp [", len(*tmp), "] + LEN a [", len(a), "]")
	fmt.Println("DEBUG: After MAKENEW: pl[", pl, "] *pl[", *pl, "] &pl[", &pl,"]")
	copy(*pl, *tmp)
	fmt.Println("DEBUG: After COPY tmp INTO: pl[", pl, "] *pl[", *pl, "] &pl[", &pl,"]")
	*pl = append(*pl, a...)
	fmt.Println("DEBUG: After APPEND NEW PORTS pl[", pl, "] *pl[", *pl, "] &pl[", &pl,"]")
	*/
}

// InitDefault() builds and returns a port list slice for netBang. It is based on (IMHO) some reasonable and usually of-interest ports. 
func InitDefault(sp string) PortList{

	var tT = []uint16{22, 135, 137, 139, 445, 623, 3389, 5040, 5985, 8000, 9999} // TEST functionality;
	var tS = []uint16{20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 135, 137, 139, 143, 177, 179, 389, 443, 445, 464, 512, 513, 514, 515, 546, 547, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1270, 1337, 1433, 1434, 1521, 2222, 2323, 2375, 2483, 2484, 3306, 3333, 3389, 5060, 5061, 5432, 5800, 5900, 8008, 8080, 8081, 8088, 8443}
	var tE = []uint16{37, 49, 70, 82, 83, 85, 109, 115, 162, 201, 220, 264, 444, 464, 497, 530, 543, 544, 601, 631, 639, 666, 749, 750, 751, 752, 843, 902, 903, 992, 1080, 1194, 1514, 1701, 1723, 1741, 1812, 1813, 2049, 2082, 2083, 2095, 2096, 2100, 2376, 2638, 3128, 3268, 3269, 3689, 4333, 4444, 5000, 6514, 6881, 8000, 8089, 6000, 6001, 6665, 6666, 6667, 6668, 6669, 8333, 8334, 8888, 9001, 9333, 10000, 12345, 18080, 18081, 19132, 20000, 31337}
	var uS = []uint16{67, 68, 69, 123, 138, 161, 162, 264, 500, 514, 520, 521, 853, 902, 1433, 1434, 1812, 1813, 2049, 3268, 3269, 3260, 3478, 3479, 3480, 3481, 4500, 4567, 5000, 5001, 5060, 10000, 11371}

	switch sp {
	case "tcp_test":
		return tT	
	case "tcp_short":
		return tS
	case "tcp_extra":
		// conjure and populate a slice able to hold both tcp port def arrays
		// Variable with len() to accommodate portlist definition updates
		tX := make([]uint16, len(tS)+len(tE), len(tS)+len(tE)+32)
		copy(tX, tS)
		tX = append(tX, tE...)
		return tX
	case "udp_short":
		return uS	
	default:
		return nil // error condition
	}
}

/******************************************************************************
PortRange

Beginning port, end port. Easy. 
******************************************************************************/
type PortRange struct {
	Start uint16
	End   uint16
}

func (pr PortRange)Size() int {
	return (int(pr.End) - int(pr.Start) + 1)
}

/********************************************************************************
ArgsToPortRange()

People need to be able to give ranges of ports. Besides, setting up a 65K+
item uint16 slice just to scan all the ports would be dumb.

Input:  String with a hyphen, indicating either a port range definition or an
	invalid input.

Output: Validated strings will return the beginning port and the ending port of
	the range.
	Invalid will return:
		Start: 0, End: 0, OR
		(invalid/NaN char value), 0

Note: was "getPortRange()" throught v0.43a
********************************************************************************/
func ArgsToPortRange(s string) PortRange {
	var prtn =  PortRange{Start: 0, End: 0}
	pr := [2]uint16{0,0}
	numwords := strings.Split(s, "-") // dudes look like a ladies
	if len(numwords) != 2 {
		log.Printf("Input error: Nonviable port range description [%s] given, no ports included from it.\n", s)
		return prtn 
	}
	for i, word := range numwords {
		port, isnum := uglynum.NumStringToInt32(word)
		if isnum {
			pr[i] = uint16(port)
			continue
		} else {
			return prtn
		}
	}
	if pr[0] > pr[1] {               // housekeeping: if not ordered "smallnum-largernum", swap em
		pr[0], pr[1] = pr[1], pr[0]
	} else if pr[0] == pr[1] {       // also: zero-range is weird, but allowed I guess. Someone will do this...
		log.Printf("Warning: Zero-range port range [%s] given. It's allowed, but weird. Did you mean to do that?\n", s)	
	}
	return PortRange{pr[0], pr[1]}	
}

/******************************************************************************
GetSocketString()

Returns a "host:port" target string usable by net.Dial() and resolveUDPAddr()
******************************************************************************/
func GetSocketString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}

