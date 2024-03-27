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

	tmp := pl
	*pl = make([]uint16, 0, len(*tmp)+len(a)) //stretch capacity out to total size
	copy(*pl, *tmp)
	*pl = append(*pl, a...)
}

func (pl *PortList)BuildNamed(sp string){

	var tT = []uint16{22, 135, 137, 139, 445, 623, 3389, 5040, 5985, 8000, 9999} // TEST functionality;
	var tS = []uint16{20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 135, 137, 139, 143, 177, 179, 389, 443, 445, 464, 512, 513, 514, 515, 546, 547, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1270, 1337, 1433, 1434, 1521, 2222, 2323, 2375, 2483, 2484, 3306, 3333, 3389, 5060, 5061, 5432, 5800, 5900, 8008, 8080, 8081, 8088, 8443}
	var tE = []uint16{37, 49, 70, 82, 83, 85, 109, 115, 162, 201, 220, 264, 444, 464, 497, 530, 543, 544, 601, 631, 639, 666, 749, 750, 751, 752, 843, 902, 903, 992, 1080, 1194, 1514, 1701, 1723, 1741, 1812, 1813, 2049, 2082, 2083, 2095, 2096, 2100, 2376, 2638, 3128, 3268, 3269, 3689, 4333, 4444, 5000, 6514, 6881, 8000, 8089, 6000, 6001, 6665, 6666, 6667, 6668, 6669, 8333, 8334, 8888, 9001, 9333, 10000, 12345, 18080, 18081, 19132, 20000, 31337}
	var uS = []uint16{67, 68, 69, 123, 138, 161, 162, 264, 500, 514, 520, 521, 853, 902, 1433, 1434, 1812, 1813, 2049, 3268, 3269, 3260, 3478, 3479, 3480, 3481, 4500, 4567, 5000, 5001, 5060, 10000, 11371}

	switch sp {
	case "tcp_test":
		copy(*pl, tT)
	case "tcp_short":
		copy(*pl, tS)
	case "tcp_extra":
		// conjure and populate a slice able to hold both tcp port def arrays
		// Variable with len() to accommodate portlist definition updates
		tX := make([]uint16, len(tS)+len(tE), len(tS)+len(tE)+32)
		copy(tX, tS)
		tX = append(tX, tE...)
		copy(*pl, tX)
	case "udp_short":
		copy(*pl, uS)
	default:
		*pl = nil // error condition
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

/******************************************************************************
getSocketString()

Returns a "host:port" target string usable by net.Dial() and resolveUDPAddr()
******************************************************************************/
func GetSocketString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}

/********************************************************************************
doPortsFinal()

take user-defined data string, parse and convert numbers, identify named lists,
then append all to Netdeets.Portlist
********************************************************************************/
func DoPortsFinal(udd string) {
	pn, nl := ParsePortsCdl(udd) // convert port strings to uint16; separate port numbers (pn) from named lists (nl)
	if len(nl) > 0 { // if we have named lists...
		for i := 0; i < len(nl); i++ { // ...parse each...
			// resize the portlist appropriately and reassemble
			newports := BuildNamedPortsList(nl[i]) // ...into a []uint16 slice...
			if newports != nil {                   // ...and if each is valid...
				AddPortsToPortsList(newports) // ...add to master list
			} else {
				log.Fatalf("Error: Undefined list given: \"%s\"", nl[i])
			}
		}
	}
}

/******************************************************************************
ParsePortsCdl()

Input: Comma-delimited string of possible ports, named port lists, or port
number range. Uses numStringToInt32() to extract portnumbers in usable
numeric form, and flags when the value in the list is not a number.

Updates identified port ranges to NetDeets.BangSpan.

Returns:

	 	Ports: []uint16
		(assumed) port ranges: []string

TODO:

2) Dedup list (not sure here is the place tho)

******************************************************************************/
func ParsePortsCdl(s string) ([]uint16, []string) {
	var r1 []string  // named lists     ex: {"tcp_extra"}
	var r2 []uint16  // ports           ex: {22,23,80,3389}
	var pr PortRange // port range defs ex: {"80-90","100-3000"}
	var port int32
	var isnum bool
	// fmt.Println("\nParsePortsCDL input string: ", s) TEST
	list := strings.Split(s, ",")
	for _, item := range list { // Eval each list item
		port, isnum = NumStringToInt32(item)
		if isnum == false { // put the name in the list of names
			if port == 45 { // 45d is 0x2d, a.k.a. the hyphen. Possible num1-num2 range.
				pr.Start, pr.End = GetPortRange(item) // Check port range def and populate BangSpan if valid
				if pr.End != 0 {
					ThisScan.NetDeets.BangSpan = append(ThisScan.NetDeets.BangSpan, pr)
				}
			} else { // Assume a "named list"; send to named lists eval
				r1 = append(r1, item)
			}
		} else { // put numbers in the list of ports
			r2 = append(r2, uint16(port))
		}
	}
	// fmt.Println("\nPort range defs strings slice: ", r0) // TEST
	// fmt.Println("\nNamed portlist strings slice: ", r1) // TEST
	// fmt.Println("\nUint16 ports slice: ", r2)  // TEST
	return r2, r1
}

/*
*******************************************************************************
getPortRange()

People need to be able to shorthand portrange defs. Besides, setting up a 65K+
item uint16 slice just to scan all the ports would be dumb.

Input:  String with a hyphen, indicating either a port range definition or an

	invalid input.

Output: Validated strings will return the beginning port and the ending port of

	the range.
	Invalid will return:
		0,0, OR
		(invalid/NaN char value), 0

*******************************************************************************
*/
func GetPortRange(s string) (uint16, uint16) {
	var pr = []uint16{0, 0}
	numwords := strings.Split(s, "-")
	if len(numwords) != 2 {
		return 0, 0
	}
	for i, numwd := range numwords {
		port, isnum := numStringToInt32(numwd)
		if isnum {
			pr[i] = uint16(port)
			continue
		} else {
			return uint16(port), 0
		}
	}
	if pr[0] > pr[1] { // if not begin-smallnum, end-largernum, swap em
		pr[0], pr[1] = pr[1], pr[0]
	}
	return pr[0], pr[1]
}

/********************************************************************************
numStringToInt32()

Input: A string, expectedly some representation of a portnum integer 0-65535
Output: The int32 value represented by the string and boolean validation that

	it was a valid integer (TRUE); OR
	The first out-of-bounds character that showed the input to be NaN, and
	boolean FALSE.

Examples: Input: "132"  [0x31,0x33,0x32]         Output: 132 [0x84],true

	      Input: "test" [0x74,0x65,0x73,0x74]    Output: 116 [0x74],false
		  Input: "7-23" [0x37,0x2D,0x32,0x33]    Output: 45  [0x2D],false

Q&A time:
Q: HEY! We're doing port math with uint16 numbers, why is this defaulting to
int32? (Great question.)
A: Since other runes may sneak in, including erroneous input or valid list
names, and since we use "-48d (-0x30)" subtraction to convert the Ascii
representationof a number to an actual number, negative int values are possible
and must be handled as signed to prevent bad validation resulting from unsigned
wraparound. That is why this uses int32 and not uint16. We can recast after
we're done farting around.
********************************************************************************/
func NumStringToInt32(snr string) (int32, bool) {
	var tot int32 = 0
	isnum := false               // I'll believe you're supposed to be a number when you show me you behave like one...
	snr = strings.TrimSpace(snr) // be nice and trim it up, just in case
	// fmt.Println("\nItem: ", []byte(snr)) //TEST
	slen := len([]rune(snr))
	for i := slen - 1; i >= 0; i-- { // build the number, by walking the chars
		char := snr[i]
		if (int32(char)-48 < 0) || (int32(char)-48) > 9 { // if char is not 0-9
			//fmt.Printf("Char is OOB! c[0x%x] d[%d]", char, int32(char)-48) TEST
			return int32(char), false // return OOB/NaN char value + FALSE
		} else {
			// fmt.Printf("Num char is %c", char) // TEST
			isnum = true
			// Use positional exponent math to compute value.
			// This is, if I am thinking about this correctly, computationally less expensive than using math.Pow10 and float64s :)
			var mplr int32 = 1 // multiplier, to rebuild our port num piece by piece
			if char != '0' {   // only when we have a non zero num to compute
				digit := slen - 1 - i // len-1-i is most signif. digit L->R
				for j := digit; j > 0; j-- {
					mplr = mplr * 10
				}
				// fmt.Printf(" times %d (x10^%d)", mplr, digit) TEST
				tot = tot + (int32(char)-48)*mplr
				// fmt.Printf(", totaling %d\n", tot)
			}
		}
	}
	return tot, isnum
}
