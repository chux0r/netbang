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
echo -n " -- GO version: " && go version
echo -n " -- Platform OS/arch details: " && uname -a


printf "\n\n=============BUILD: go build ./netbang.go ./recon.go ./resolver.go"

go build ./netbang.go ./recon.go ./resolver.go


printf "\nNETBANG TEST CASES:\n"
echo "./netbang"

./netbang 


printf "\n=============BASIC SCAN-BY-HOSTNAME: ./netbang scanme.org\n"

./netbang scanme.org #default tcp scan, using portlist "tcp_short"


printf "\n=============UDP SCAN, PORTS DEFINED IN FILE, CUSTOM TIMEOUT ./netbang --proto udp --portsfile ../netbang_ports.tmp -t 500 127.0.0.1\n"
echo -n "53,161,10000" > ../netbang_ports.tmp && printf "\n\tFILE INJECT ../netbang_ports.tmp:" && cat ../netbang_ports.tmp && printf "\n"

./netbang --proto udp --portsfile ../netbang_ports.tmp -t 500 127.0.0.1 && rm ../netbang_ports.tmp ## tcp scan, ports defined in file


printf "\n=============EXECUTE: ./netbang --recon list\n"

./netbang --recon list # list recon modes


printf "\n=============EXECUTE: ./netbang --recon dns amazon.com\n"

./netbang --recon dns amazon.com # get dns info


printf "\n=============EXECUTE: ./netbang --recon dns --ns 8.8.8.8 github.com\n"

./netbang --recon dns --ns 8.8.8.8 github.com #get dns info, use custom resolver


printf "\n=============EXECUTE: ./netbang --recon shodan hostip 1.1.1.1\n"

./netbang --recon shodan hostip 1.1.1.1 # query shodan data using host ip NOTE: this test only works when $SHODAN_KEY is defined/valid  
