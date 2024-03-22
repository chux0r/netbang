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

type NameSvr struct {
	DnsDialer	*net.Dialer
	IPAddr		net.IP
	Port		uint16
}

var Ns = NameSvr{
	DnsDialer: &net.Dialer{
		Timeout: time.Second * time.Duration(5), // default is NO FUCKING TIMEOUT... uhh yeah always set this
		FallbackDelay: 300 * time.Millisecond,   // ipv6 fallback (default, but want to be intentional here)
		KeepAlive: -1,                           // no keepalives. Our Timeout is shorter anyway. We'll deal.
	},
	IPAddr:	net.IP{1,1,1,1},                     // TODO: link this to --resolver flag
	Port: 53,
}
 
/******************************************************************************
(*DnsData).resolve()

DNS lookup of a hostname (forward) or IP (reverse) string.
Populates DnsData with any/all resolved IPs.

Also: Since we do not want to use Go or Google default resolver configs, this
always sets up a custom dialer for name resolution
******************************************************************************/
func (dd *DnsData)resolve(s string) error { 
	var err error
	dd.Dns.StrictErrors = false // enable partial results
	resolvr := getSocketString(Ns.IPAddr.String(), Ns.Port) //"default: 1.1.1.1:53 (Cloudflare dns)"     
	ctx := context.Background()
	dd.Dns.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//d := net.Dialer{Timeout: time.Second * time.Duration(5)}
		return Ns.DnsDialer.DialContext(ctx, network, resolvr)
	}
	fmt.Printf("\nDNS lookup: [%s] Resolver: [%s] Port: %d\n", s, Ns.IPAddr.String(), Ns.Port)
	// eval: IP, hostname, or "other" 
	t := net.ParseIP(s)
	if t != nil {	// is IP, do reverse lookup instead
		fmt.Print(" (reverse lookup)")
		dd.RevNames, err = dd.Dns.LookupAddr(ctx, s)
		if err != nil {
			log.Print("DNS resolution error: [", err, "]\n")
			return err
		}
		fmt.Printf("\nHost %s resolves as:\n", s)
		for j, n := range dd.RevNames {
			fmt.Printf("\tIP #%d: %s\n", j+1, n)
		}
		return err
	} // continue
	dd.IPs, err = dd.Dns.LookupHost(ctx, s)
	if err != nil {
		log.Print("DNS resolution error: [", err, "]\n")
		return err
	}
	fmt.Printf("\nHost [%s] resolves as:\n", s)
	for j, ip := range dd.IPs {
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
