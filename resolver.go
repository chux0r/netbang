package main

/******************************************************************************
resolver.go

DNS resolution functions in here to help netscanx change resolvers and dig out
DNS records and zone info for given targets

Author: CT Geigner "chux0r"
******************************************************************************/
import (
	"context"
	"fmt"
	"net"
	"time"
)

/*
*****************************************************************************
setCustomResolver

Sets a custom resolver, by IP. Port 53 is assumed.
Ex: setCustomResolver(&Resolv.Dns, "8.8.8.8")
*****************************************************************************
*/
func setCustomResolver(dns *net.Resolver, ip string) {
	dnsHost := getSocketString(ip, uint16(53)) // TODO :: validate given IP
	dns.PreferGo = true
	dns.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * time.Duration(5), // FUTURE CONSIDERATION: Set custom timeout?
		}
		return d.DialContext(ctx, network, dnsHost)
	}
}

/*
*****************************************************************************
resolveName()

Accepts a hostname or IP string and populates global DnsData with any/all
resolved IPs.
*****************************************************************************
*/
func resolveName(s string) { // var Resolv DnsData is a global struct
	var err error
	ctx := context.Background() // TODO: determine which context would be most helpful. Using Background() for now
	t := net.ParseIP(s)         // TODO: move to whatTargetType() func. Answers: is target a FQDN or an IP?
	if t != nil {               // if Target is an IP
		ThisScan.Target.Ip = []byte(s)
		ThisScan.Target.isIp = true
	} else { // if Target is a hostname/FQDN
		ThisScan.Target.isHostn = true
		fmt.Printf("DNS Lookup for %s: \n", s)
		Resolv.Addrs, err = Resolv.Dns.LookupHost(ctx, s)
		if err != nil {
			fmt.Printf("Error: [")
			fmt.Print(err)
			fmt.Printf("]\n")
		} else {
			for i, addr := range Resolv.Addrs {
				fmt.Printf("\tIP #%d: %s\n", i+1, addr)
			}
		}
		fmt.Printf("(DNS lookup complete)\n") // TEST
	}
}
