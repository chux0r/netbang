package main

/******************************************************************************
* portscan.go
*
* Functions used by netscanx specifically to support smart and quick port
* selection, and teeing up TCP and UDP scans
*
* CT Geigner ("chux0r")
* 21 SEPT 2023
*
******************************************************************************/

import (
	"fmt"
	"log"
	"strings"
)

/* scanConstructor() just starts us off with some sensible default values. Most defaults aim at "tcp scan" */
func scanConstructor() {
	thisScan.NetDeets.Protocol = "tcp"
	thisScan.NetDeets.PortList = buildNamedPortsList("tcp_short")
	thisScan.Target.isIp = false
	thisScan.Target.isHostn = false
	thisScan.Target.Addr = "127.0.0.1"
}

/* buildNamedPortsList() returns a slice of named, prebuilt uint16 port numbers useful for TCP and UDP scanning */
func buildNamedPortsList(sp string) []uint16 {

	var tT = []uint16{135, 137, 139, 445, 623, 3389, 5040, 5985, 8000, 9999} // TEST functionality; windows hosts
	var tS = []uint16{20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113, 119, 135, 137, 139, 143, 177, 179, 389, 443, 445, 464, 512, 513, 514, 515, 546, 547, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1270, 1337, 1433, 1434, 1521, 2222, 2323, 2375, 2483, 2484, 3306, 3333, 3389, 5060, 5061, 5432, 5800, 5900, 8008, 8080, 8081, 8088, 8443}
	var tE = []uint16{37, 49, 70, 82, 83, 85, 109, 115, 162, 201, 220, 264, 444, 464, 497, 530, 543, 544, 601, 631, 639, 666, 749, 750, 751, 752, 843, 902, 903, 992, 1080, 1194, 1514, 1701, 1723, 1741, 1812, 1813, 2049, 2082, 2083, 2095, 2096, 2100, 2376, 2638, 3128, 3268, 3269, 3689, 4333, 4444, 5000, 6514, 6881, 8000, 8089, 6000, 6001, 6665, 6666, 6667, 6668, 6669, 8333, 8334, 8888, 9001, 9333, 10000, 12345, 18080, 18081, 19132, 20000, 31337}
	var uS = []uint16{67, 68, 69, 123, 138, 161, 162, 264, 500, 514, 520, 521, 853, 902, 1433, 1434, 1812, 1813, 2049, 3268, 3269, 3260, 3478, 3479, 3480, 3481, 4500, 4567, 5000, 5001, 5060, 10000, 11371}

	switch sp {
	case "tcp_test":
		return tT
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
		return nil // error condition
	}
}

/*
*****************************************************************************
getHostPortString()

Returns a "host:port" target string usable by net.Dial() and resolveUDPAddr()
*****************************************************************************
*/
func getHostPortString(t string, p uint16) string {
	s := fmt.Sprintf("%s:%d", t, p)
	return s
}

/*
*****************************************************************************
addPortsToPortsList()

Add a slice of []uint16 to NetDeets.Portlist
*****************************************************************************
*/
func addPortsToPortsList(a []uint16) {

	tmp := thisScan.NetDeets.PortList
	// the LEN should not be > 0? I think I did this wrong. Try setting len to zero, but capacity to len.tmp+len.a+32 // thisScan.NetDeets.PortList = make([]uint16, len(tmp)+len(a), len(tmp)+len(a)+32)
	thisScan.NetDeets.PortList = make([]uint16, 0, len(tmp)+len(a)) //stretch capacity out to total size
	copy(thisScan.NetDeets.PortList, tmp)
	thisScan.NetDeets.PortList = append(thisScan.NetDeets.PortList, a...)

}

/*
*******************************************************************************
doPortsFinal()

take user-defined data string, parse and convert numbers, identify named lists,
then append all to Netdeets.Portlist
*******************************************************************************
*/
func doPortsFinal(udd string) {
	p, pl := parsePortsCdl(udd) // convert port strings to uint16; separate port numbers (p) from named lists (pl)
	addPortsToPortsList(p)
	if len(pl) > 0 { // if we have named lists...
		for i := 0; i < len(pl); i++ { // ...parse each...
			// resize the portlist appropriately and reassemble
			newports := buildNamedPortsList(pl[i]) // ...into a []uint16 slice...
			if newports != nil {                   // ...and if each is valid...
				addPortsToPortsList(newports) // ...add to master list
			} else {
				log.Fatalf("Error: Undefined list given: \"%s\"", pl[i])
			}
		}
	}
}

/*
*****************************************************************************
parsePortsCdl()

Parses the comma-delimited string passed in by the user, using the --ports
flag. Since the user can specify either numbers or port list names, uses
numStringToInt32() to extract portnumbers in usable numeric form, and flags
when the value in the list is not a number.
Returns ports as []uint16, any (assumed) named port lists as []string.
*****************************************************************************
*/
func parsePortsCdl(s string) ([]uint16, []string) {
	var r1 []string
	var r2 []uint16
	var port int32
	var isnum bool
	// fmt.Println("\nParsePortsCDL input string: ", s) TEST
	list := strings.Split(s, ",")
	for _, item := range list { // Eval each list item
		port, isnum = numStringToInt32(item)
		if isnum == false { // put the name in the list of names
			r1 = append(r1, item)
		} else { // put the port in the list of ports
			r2 = append(r2, uint16(port))
		}
	}
	// fmt.Println("\nStrings slice: ", r1) // TEST
	// fmt.Println("\nuint16 slice: ", r2)  // TEST
	return r2, r1
}

/*
*******************************************************************************
numStringToInt32()

Input: A string, expectedly some representation of a portnum integer 0-65535
Output: The int32 value represented by the string and boolean validation that

	it was a valid integer(TRUE); or the first out-of-bounds character that
	showed the input to be NaN, and boolean FALSE

Examples: Input: "132"  [0x49,0x51,0x50]          Output: 132,true

	Input: "test" [0x116,0x101,0x115,0x116] Output: 116,false

Q&A time:
Q: HEY! We're doing port math with uint16 numbers, why is this defaulting to
int32? (Great question.)
A: Since other runes may sneak in, including erroneous input or valid list
names, and since we use "-48" subtraction to convert the Ascii representation
of a number to an actual number, negative int values are possible and must be
handled as signed to prevent bad validation resulting from unsigned wraparound.
That is why this uses int32 and not uint16. We can recast after we're done
farting around.
*******************************************************************************
*/
func numStringToInt32(snr string) (int32, bool) {
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
