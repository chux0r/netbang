package main

import (
	"net"
	"testing"
)

// test that resolution happens, and that DnsData.IPs is populated
func TestGetWithHostN(t *testing.T) {
	hostTarget := "example.com" // iana standard test domain- works!
	var testDnsData DnsData
	
	err := testDnsData.get(hostTarget)
	if err != nil {
		t.Fatalf("[DnsData].get(%s): %s", hostTarget, err.Error())
	}
	if len(testDnsData.IPs) < 1 {
		t.Fatalf("[DnsData].get(%s): After lookup success, no IPs captured! (IP count crosscheck: [%d])", hostTarget, len(testDnsData.IPs))
	}
}

// test that revlookup happens, and that DnsData.RevNames is populated 
func TestGetWithIP(t *testing.T) {
	ipTarget   := "1.1.1.1" // example.com's IP has no reverse. I wish there was a static standard to use. I guess 1.1.1.1 should be reasonably ok in the medium-term (Clouflare's DNS, revlooks to "one.one.one.one". pretty cool.) 
	
	var testDnsData DnsData
	
	err := testDnsData.get(ipTarget)
	if err != nil {
		t.Fatalf("[DnsData].get(%s): %s", ipTarget, err.Error())
	}
	if len(testDnsData.RevNames) < 1 {
		t.Fatalf("[DnsData].get(%s): After lookup success, no Hostnames captured! (Host count crosscheck: [%d])", ipTarget, len(testDnsData.RevNames))
	}
}

// Test setting ipaddr:port on the dialer for used for DNS lookups
func TestSetResolver(t *testing.T) {
	var testNameServer NameSvr
	
	setdns := "1.1.1.1:443"
	var wantip = net.IP{1,1,1,1}
	wantport := 443
	
	err := testNameServer.setResolver(setdns) 
	if err != nil {
		t.Fatalf("[NameSvr].setResolver(%s): %s", setdns, err.Error())
	}
	
	if !testNameServer.IPAddr.Equal(wantip) {
		t.Fatalf("[NameSvr].setResolver(%s): Fail. NameSvr.IPAddr set [%v]; want [%+v]", setdns, testNameServer.IPAddr, wantip)
	} 
	if testNameServer.Port != uint16(wantport){
		t.Fatalf("[NameSvr].setResolver(%s): Fail. NameSvr.Port set [%v]; want [%d]", setdns, testNameServer.Port, wantport)
	} 
	
}