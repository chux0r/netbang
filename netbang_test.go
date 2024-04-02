package main

import (
	"testing"
	"net"
)

// test that resolution happens, and that DnsData.IPs is populated
func TestScanConstruct(t *testing.T){
	var wantip = net.IP{127,0,0,1}
	sl := 65
	ctx := "bangspan"
	var testTarg = ScanSpec{}  // test against empty useless struct
	testTarg.Init(ctx)
	if len(testTarg.NetDeets.PortList) != sl {
		t.Fatalf("(*ScanSpec)Init(%s): Error. Portlist set: [%d]; Want: [%d]",ctx, len(testTarg.NetDeets.PortList), sl)	
	} else if !testTarg.Targ.Ip.Equal(wantip) {
		t.Fatalf("(*ScanSpec)Init(%s): Error. IPAddr set: [%v]; Want: [%v]",ctx, len(testTarg.Targ.Ip), wantip)
	}  
	
}