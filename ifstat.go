package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
)

/*
*******************************************************************************
ifstat()

Get and display some network interface info on whatever rig from which the user
decides to launch this mofo. Target linux, windows, darwin/MACOS. Maybe android
and bsds later. AIX never LOL IBM...

--ctg
29DEC2023
*******************************************************************************
*/
func ifstat() {

	/*
	Based on operating system, dump some useful network info: MIN: interface, IP, gateway/route
	To see all OS/arch combos, run: >go tool dist list
	*/
	switch runtime.GOOS {
	case "linux":
		cmd := "/usr/sbin/ip" // don't expect that /usr/sbin will be in anyone's default $PATH. Calling "ip" explicitly.
		path, err := exec.LookPath(cmd)
		if err != nil {
			log.Printf("Command exec error: [%s] OS: [%s] CMD: [%s]", err.Error(), runtime.GOOS, cmd)
			return
		}
		outp, err := exec.Command(path, "route").Output()
		fmt.Printf("\nNetwork gateway/IF/IP:\n%s", string(outp))
		outp, err = exec.Command(path, "link", "show", "up").Output()
		fmt.Printf("\nInterfaces/state/MAC:\n%s", string(outp))
	case "windows":
		cmd := "powershell"
		path, err := exec.LookPath(cmd)	
		if err != nil {
			log.Printf("Command exec error: [%s] OS: [%s] CMD: [%s]", err.Error(), runtime.GOOS, cmd)
			return
		}
		outp, err := exec.Command(path, "Get-NetIPConfiguration").Output()
		fmt.Printf("\nNetwork gateway/IF/IP:\n%s", string(outp))
	default:
		fmt.Printf("OS: %s -- Network interface info unsupported in OS\"%s\".\n", runtime.GOOS, os.Args[0])
	}
}
