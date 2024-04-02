###############################################################################
# Powershell script :: build test for windows schtuff
# 
# CTG "chux0r"
# 02APR2024 
###############################################################################

Get-Host
$env:PROCESSOR_ARCHITECTURE
Get-date
go version
go build ./netbang.go ./recon.go ./resolver.go
Write-Output "==========================================="
.\netbang.exe
Write-Output  "==========================================="
.\netbang scanme.org #default tcp scan, using portlist "tcp_short"
Write-Output  "==========================================="
Set-Content -Path ..\netbang_ports.tmp -Value "53,161,10000"
.\netbang --proto udp --portsfile ..\netbang_ports.tmp -t 500 127.0.0.1 
Remove-Item ../netbang_ports.tmp ## tcp scan, ports defined in file
Write-Output  "==========================================="
.\netbang --recon list # list recon modes
Write-Output  "==========================================="
.\netbang --recon dns amazon.com # get dns info
Write-Output  "==========================================="
.\netbang --recon dns --ns 8.8.8.8 github.com #get dns info, use custom resolver
Write-Output  "==========================================="
.\netbang --recon shodan hostip 1.1.1.1 # query shodan data using host ip NOTE: this test only works when $SHODAN_KEY is defined/valid  
