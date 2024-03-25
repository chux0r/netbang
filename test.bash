#!/bin/bash
###############################################################################
# nb_build_test.bash
# 
# outputs env + exercises netbang functionality via invocation.
# This should compliment _test.go unit testing stuff.
# OMG DO NOT USE THIS IN LIEU OF GO TESTING.
#
# Run only in build directory. Won't find anything otherwise
#
# CTG "chux0r"
# 25MAR2024
#
###############################################################################

echo "Build test by: ${USER}@${HOSTNAME}:${PWD}" 
echo -n "Date:" && date
echo -n "GO version" && go version
echo -n "Platform OS/arch details:" && uname -a
echo "go build ./netbang.go ./ifstat.go ./portfu.go ./recon.go ./resolver.go"
go build ./netbang.go ./ifstat.go ./portfu.go ./recon.go ./resolver.go
echo "NETBANG TEST CASES:"
echo "./netbang"
./netbang 
echo "=============EXECUTE: ./netbang 127.0.0.1"
./netbang 127.0.0.1 #default tcp scan, using portlist "tcp_short"
echo "=============EXECUTE: \"53,161,10000\" -> ../netbang_ports.tmp"
echo "./netbang --proto udp --portsfile ../netbang_ports.tmp -t 500 127.0.0.1 && rm ../netbang_ports.tmp"
echo -n "53,161,10000" > ../netbang_ports.tmp && echo -n "../netbang_ports.tmp:" && cat ../netbang_ports.tmp
./netbang --proto udp --portsfile ../netbang_ports.tmp -t 500 127.0.0.1 && rm ../netbang_ports.tmp ## tcp scan, ports defined in file
echo "=============EXECUTE: ./netbang --recon list"
./netbang --recon list # list recon modes
echo "=============EXECUTE: ./netbang --recon dns amazon.com"
./netbang --recon dns scanme.org # get dns info
echo "=============EXECUTE: ./netbang --recon dns --ns 8.8.8.8 github.com"
./netbang --recon dns --ns 8.8.8.8 github.com #get dns info, use custom resolver
echo "=============EXECUTE: ./netbang --recon shodan hostip 1.1.1.1"
./netbang --recon shodan hostip 1.1.1.1 # query shodan data using host ip NOTE: this test only works when $SHODAN_KEY is defined/valid  
