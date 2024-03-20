package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ns3777k/go-shodan/v4/shodan"
)

var Rmethods = []string{
	"\"shodan\" :: Shodan is a search engine for Internet-connected devices. Requires API key. See https://developer.shodan.io/api",
}

// shodn() takes a method, an api key, and a target ip. If the API key is set as an environment var, pass an empty string.
func shodn(methd string, akey string, targ string) {
	keyn := "SHODAN_KEY" // API key might be set in the OS env
	//ns3777k's go-shodan relies on the API key being set in users' environments as "SHODAN_KEY"
	//We'll check there, and allow manual input as well
	switch strings.ToLower(methd) { // Shodan methods implemented here. see https://developer.shodan.io/api
	case "hostip":
		var hso shodan.HostServicesOptions
		// check to see if API key is supplied in one or both ways
		val, ok := os.LookupEnv(keyn)
		//if conflicting env, print warning and execute
		if (ok && val != "") && akey != "" {        // osenv SHODAN_KEY set, but also sent a key in the args
			log.Printf("\"Notice: %s: %s\" set in OS ENV; but other API key given. Using key set explicitly: [%s].", keyn, val, akey)
		} else if (ok && val != "") && akey == "" { // osenv set, no api key passed in args
			cli := shodan.NewEnvClient(nil)
			targetdata, err := cli.GetServicesForHost(context.Background(), targ, &hso)
			if err != nil {
				log.Fatalf("Error getting Shodan data for target %s", targ)
			}
			fmt.Printf("\nUnparsed Shodan data for target %s:\n%v\n\n", targ, targetdata)
		} else if (!ok || val == "") && akey != "" { // osenv not set, key given
			cli := shodan.NewClient(nil, akey)
			targetdata, err := cli.GetServicesForHost(context.Background(), targ, &hso)
			if err != nil {
				log.Fatalf("Error getting Shodan data for target %s", targ)
			}
			fmt.Printf("\nUnparsed Shodan data foor target %s:\n%v", targ, targetdata)
		} else { // no key, no env, outta options
			log.Fatalf("No Shodan API key set! Exiting")
		}
	default:
		log.Fatalf("Unhandled Shodan method: \"%s\"", methd) //No hit, therefore log as invalid
	}
}