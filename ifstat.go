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
	   Find out what OS we're on, one of the following Operating Systems:
	   aix, android, darwin, dragonfly, freebsd, illumos, ios, js, linux, netbsd, openbsd, plan9, solaris, windows
	   To see all OS/arch combos, run: >go tool dist list
	*/
	opsys := runtime.GOOS
	switch opsys {
	case "linux":
		cmd := "/usr/sbin/ip" // don't expect that /usr/sbin will be in anyone's default $PATH. Calling "ip" explicitly.
		path, err := exec.LookPath(cmd)
		if err != nil {
			log.Printf("Command exec error: [%s] OS: [%s] CMD: [%s]", err.Error(), opsys, cmd)
			return
		}
		outp, err := exec.Command(path, "route").Output()
		fmt.Printf("\nNetwork gateway/IF/IP:\n%s", string(outp))
		outp, err = exec.Command(path, "link", "show", "up").Output()
		fmt.Printf("\nInterfaces/state/MAC:\n%s", string(outp))
	default:
		fmt.Printf("OS: %s -- Network interface info unsupported in OS\"%s\".\n", opsys, os.Args[0])
	}
}
