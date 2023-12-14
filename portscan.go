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
flag. Since the user can specify either numbers or port list names, the func
must detect item type 1st, then perform validation. In the case of port
numbers, since we bring everything as string data, there is some fun converting
runes. Returns ports as []uint16, any named port lists as []string.
*****************************************************************************
*/
func parsePortsCdl(s string) ([]uint16, []string) {
	var r1 []string
	var r2 []uint16
	fmt.Println("\nParsePortsCDL input string: ", s)
	list := strings.Split(s, ",")
	for _, item := range list { // Eval each list item
		item = strings.TrimSpace(item)        // be nice and trim it up, just in case
		fmt.Println("\nItem: ", []byte(item)) //TEST
		num := false
		var tot int32 = 0
		itlen := len([]rune(item))
		for i := itlen - 1; i >= 0; i-- { // walk the chars
			char := item[i]
			if (int32(char)-48 < 0) || (int32(char)-48) > 9 { // if char is not 0-9
				fmt.Printf("Illegal char! c[0x%x] d[%d]", char, int32(char)-48)
				num = false
				break // if NaN, break out
			} else { // Numeric; convert and calc
				num = true
				var mlt int32 = 1                  // multiplier, to rebuild our port num piece by piece``
				fmt.Printf("Num char is %c", char) // TEST
				if char != '0' {                   // only when we have a non zero num to compute
					digit := itlen - 1 - i // len-1-i is most signif. digit L->R
					//if digit > 0 {
					for j := digit; j > 0; j-- { // computationally less expensive than using math.Pow10 and float64s :)
						mlt = mlt * 10
					}
					//}
					fmt.Printf(" times %d (x10^%d)", mlt, digit)
					tot = tot + (int32(char)-48)*mlt
					fmt.Printf(", totaling %d\n", tot)
				}
			}
		}
		if num == false { // put the name in the list of names
			r1 = append(r1, item)
		} else { // put the port in the list of ports
			r2 = append(r2, uint16(tot))
		}
	}
	fmt.Println("\nStrings slice: ", r1) // TEST
	fmt.Println("\nuint16 slice: ", r2)  // TEST
	return r2, r1
}
