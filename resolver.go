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
	"log"
	"net"
	"strings"
	"time"

	"chux0r.org/portfu"
	"chux0r.org/uglynum"
)

type DnsData struct {
	Dns      net.Resolver // DNS fun, but mostly lookups/resolution
	IPs      []string     // IPs resolved: future: need to convert to []net.IP/support IPv6
	RevNames []string     // IP reverse-lookup names
}

/******************************************************************************
(*DnsData).get()

Populate *DnsData by doing DNS hostname (forward) or IP (reverse) lookup.

Also: Since we do not want to use Go or Google default resolver configs, this
always sets up a custom dialer for name resolution
******************************************************************************/
func (dd *DnsData)get(s string) error { 
	var err error
	dd.Dns.StrictErrors = false // enable partial results
	resolvr := portfu.GetSocketString(Nsd.IPAddr.String(), Nsd.Port) //"default: 1.1.1.1:53 (Cloudflare dns)"     
	ctx := context.Background()
	dd.Dns.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//d := net.Dialer{Timeout: time.Second * time.Duration(5)}
		return Nsd.DnsDialer.DialContext(ctx, network, resolvr)
	}
	fmt.Printf("\nDNS lookup: [%s] Resolver: [%s] Port: %d", s, Nsd.IPAddr.String(), Nsd.Port)
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

type NameSvr struct {
	DnsDialer	*net.Dialer
	IPAddr		net.IP
	Port		uint16
}

// Name service dialer
var Nsd = NameSvr{
	DnsDialer: &net.Dialer{
		Timeout: time.Second * time.Duration(5), // default is NO FUCKING TIMEOUT... uhh yeah always set this
		FallbackDelay: 300 * time.Millisecond,   // ipv6 fallback (default, but want to be intentional here)
		KeepAlive: -1,                           // no keepalives. Our Timeout is shorter anyway. We'll deal.
	},
	IPAddr:	net.IP{1,1,1,1},                     // TODO: link this to --resolver flag
	Port: 53,
}

/******************************************************************************
setResolver

Defines a custom resolver to use by IP and (optionally) port number
Ex: setResolver("8.8.8.8:53")
******************************************************************************/
func (n *NameSvr)setResolver(ipp string) error {
	nsdef := strings.Split(ipp, ":")
	n.IPAddr = net.ParseIP(nsdef[0])
	if n.IPAddr == nil {
		return fmt.Errorf("nameserver-set error: invalid address [%s]", nsdef[0])
	}
	if len(nsdef) >= 2 {
		if len(nsdef) > 2 {
			log.Printf("Warning: Nameserver-set overloaded. Sent -> [%s] Using host -> [%s] and port -> [%s], discarding excess parameters.", ipp, nsdef[0], nsdef[1])
		}
		p, valid := uglynum.NumStringToInt32(nsdef[1])
		if valid {
			n.Port = uint16(p) 
			log.Printf("Nameserver-set: [%s:%d]",n.IPAddr.String(),n.Port)
		} else {
			return fmt.Errorf("nameserver-set error: invalid port [%s]", nsdef[1])
		}
		return nil
	} else if len(nsdef) == 1 {
		log.Printf("Nameserver-set host IP: [%s]",nsdef[0])
		return nil
	} else {
		log.Fatalf("Error: Nameserver-set logic/OOB. Exiting.")
		return fmt.Errorf("Error: Nameserver-set logic/OOB")// if the code is good, the user should never end up in this branch, ever.
	}
}