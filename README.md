# netbang

Scrappy network interrogator and wringer-outer, written in Go. Result of wondering aloud how much advantage Go's concurrency might give for network scanning of all kinds. Might try true multithreading next, but getting some mileage out of the cheap thing first.    
     
**Secondary goal:** *Build features in current-challenge context: networks with vanishingly few realistic limits anymore; IPv6; increasingly so many things, you can't realistically plan to scan just every-fuckin-thing A-Z anymore. We'll never have the time.*    
**Tertiary goal:** Use this as an opportunity to explore and decide what value, if any, scanning might still hold. And what changes should be made if it does happen to still be useful?    
     
Just rethinking possibilities and features as I go; not to mention interesting features mashup, foo breakage for fun and profit, other creative/educational mayhem. How many network layers can we make this thing blow apart and report upon?    

Env: go version go1.20.7 linux/amd64   
Build using: "go build netbang.go portfu.go resolver.go"    
   
**AUTHOR: Chuck Geigner a.k.a. "mongoose", a.k.a. "chux0r"**   
    
*Copyright © 2023 CT Geigner, All rights reserved.*   
*Free to use under GNU GPL v2, see https://github/chux0r/netscanx/LICENSE.md*   
    
Written 'cause why not? Mostly for S&G.  --ctg   
