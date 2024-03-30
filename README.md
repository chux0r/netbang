# netbang  
Scrappy endpoint and network interrogator/wringer-outer written in Go.   

## What were you thinking?
+ Origin thought: Let's test what *Go concurrency* might do for network scanning". *(As it turns out, all kinds of good performance stuff)*
+ Evolved thought 1: "Let's use this to stretch out everything I know about Go, programming, cybersecurity, and networking." *NOTE: Go was my COVID "let's learn a new language" language.*
+ Evolved thought 2: "How relevant is "scanning" these days? How is the landscape and task different than they were in 1999? 2007? 2016? What are new limitations and contextual factors of scanning? What methods need to die? Which methods need to emerge and mature?"
+ Evolved thought 3: "Having explored all that, what should I implement in netbang to make it more relevant and useful today?"

## Initial factors I'm thinking a lot about
+ Resource management (time, process cycles, bandwidth, etc- *but mostly time*) in the face of:
     + The vastness of ipv6: networks with vanishingly few realistic limits anymore; There are increasingly so many things, we can't realistically plan to scan just every-fuckin-thing A-Z anymore. We'll never have enough time (ever).
+ Stealth
     + Banging away is noisy. It's easy for NG firewalls and endpoints to detect "scanning activity". What methods are quieter? For which outcomes/tasks does "banging" away still make sense? Which tasks need something different, or quieter, or "no touch?" approaches. What recon methods/TTPs would we devise? Is is still "banging" if we don't bang? =) *NOTE: I've decided: "YES, DEFINITELY." The best bang is no bang at all. Quote me on that.*  

## Features-steering thoughtsPreliminary thoughts steering some more-interesting features
+ **It's always about getting information**, not necessarily about poking everything in the fucking eye.
     + The best, stealthiest, most valuable scanning info might be achieved by *not scanning*. *This is Zen asf. Oh yeah*
     + Use data sources and APIs like Shodan to gather; prioritize this approach before thinking about banging away on the 'net.
+ To address the "not enough time in my lifetime to scan every address" problem, try what anthropologists and other survey-based researchers have known for a long time:
     + **We can't dig everything** and sift through it. We have neither the time nor the money. 
     + **Use avaliable intelligence** and artifacts to determine roughly where you *think* you'll find stuff worth finding.
     + Maximize limited resources at hand by performing **stratified random sampling** in those places

Env: go version go1.20.3 linux/amd64   
Build using: "go build *."    
   
**AUTHOR: Chuck Geigner "chux0r"**   
**ORG: Megaohm.net *Vive la resistance!***    
*Copyright © 2023,2024 CT Geigner, All rights reserved.*   
*Free to use under GNU GPL v2, see https://github/chux0r/netscanx/LICENSE.md*
