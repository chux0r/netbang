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
	"log"
)

type DnsData struct {
	Dns      net.Resolver // DNS fun, but mostly lookups/resolution
	IPs      []string     // IPs resolved: future: need to convert to []net.IP/support IPv6
	RevNames []string     // IP reverse-lookup names
}

/******************************************************************************
(*DnsData).resolve()

DNS lookup of a hostname (forward) or IP (reverse) string.
Populates DnsData with any/all resolved IPs.
******************************************************************************/
func (ns *DnsData)resolve(s string) error { 
	var err error
	resolvr := "1.1.1.1:53" // disconnected rn -- TODO: link this to --resolver flag
	ctx := context.Background()
	ns.Dns.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, resolvr)
	}
	fmt.Printf("\nDNS lookup: [%s] Resolver: [%s]\n", s, resolvr)
	// eval: IP, hostname, or "other" 
	t := net.ParseIP(s)
	if t != nil {	// is IP, do reverse lookup instead
		fmt.Print(" (reverse lookup)")
		ns.RevNames, err = ns.Dns.LookupAddr(ctx, s)
		if err != nil {
			log.Print("DNS resolution error: [", err, "]\n")
			return err
		}
		fmt.Printf("\nHost %s resolves as:\n", s)
		for j, n := range ns.RevNames {
			fmt.Printf("\tIP #%d: %s\n", j+1, n)
		}
		return err
	} // continue
	ns.IPs, err = ns.Dns.LookupHost(ctx, s)
	if err != nil {
		log.Print("DNS resolution error: [", err, "]\n")
		return err
	}
	fmt.Printf("\nHost [%s] resolves as:\n", s)
	for j, ip := range ns.IPs {
		fmt.Printf("\tIP #%d: %s\n", j+1, ip)
	}
	return err
}

/******************************************************************************
setCustomResolver

Sets a custom resolver, by IP. Port 53 is assumed.
Ex: setCustomResolver(&Resolv.Dns, "8.8.8.8")
******************************************************************************/
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
