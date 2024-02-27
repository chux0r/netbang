# netbang  
Scrappy network interrogator and wringer-outer written in Go.   

## WHAT? Another scanner in a sea of tools?   
Yeah? Maybe? Honestly though, I did not start this thinking "MOAR SCANNING TOOLS", or "NMAP, PFFFT", honest. 

## So, what *were* you thinking?

+ Prime thought: "Hey! Let's test what *Go concurrency* might do for network scanning". *As it turns out, all kinds of good performance stuff*
+ Thought #2: "Let's use Netbang to stretch out everything I know about programming, cybersecurity, and networking." *While learning Go, which was new to me at the time*

## After working on it a bit, chux0r had bigger, serious-er thoughts
+ The more I developed, the more I thought about the role of scanning, the value and limitations of scanning; the future of scanning.
+ Resource management (time, process cycles, bandwidth, etc- *but mostly time*) in the face of:
     + The vastness of ipv6: networks with vanishingly few realistic limits anymore; There are increasingly so many things, we can't realistically plan to scan just every-fuckin-thing A-Z anymore. We'll never have enough time (ever).
     + **We'd do well to get smart about it.**     
+ I should use *netbang* as an opportunity to explore and decide what value, if any, scanning might still hold. And what changes should be made if it does happen to still be useful?

## Preliminary thoughts steering some more-interesting features
+ It's about getting information, not about poking everything in the eye.
     + The best, stealthiest, most valuable scanning is achieved by *not scanning*. *This is Zen asf. Oh yeah*
     + Use data sources and APIs like Shodan to gather; prioritize this approach before thinking about banging away on the 'net.
+ To address the "not enough time in my lifetime" problem, try what anthropologists and other survey-based researchers have known for a long time:
     + **We can't dig everything** and sift through it. We have neither the time nor the money. 
     + **Use avaliable intelligence** and artifacts to determine roughly where you *think* you'll find stuff worth finding.
     + Maximize limited resources at hand by performing **stratified random sampling** in those places
      
Just rethinking possibilities and features as I go; not to mention interesting features mashup, foo breakage for fun and profit, other creative/educational mayhem. How many network layers can we make this thing blow apart and report upon?    

Env: go version go1.20.7 linux/amd64   
Build using: "go build *.go"    
   
**AUTHOR: Chuck Geigner "chux0r"**   
**ORG: Megaohm.net *Vive la resistance!***    
*Copyright © 2023,2024 CT Geigner, All rights reserved.*   
*Free to use under GNU GPL v2, see https://github/chux0r/netscanx/LICENSE.md*   
    
Written 'cause why not? Mostly for S&G.     
Yes, I was "mongoose", a long, long time ago. --ctg  
