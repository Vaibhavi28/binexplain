---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/31c3-ctf-2014/malware/roll/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: rop_chain
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a rop_chain vulnerability to hijack the control flow.
---
# 31C3 CTF 2014: Roll

**Category:** malware
**Points:** 30
**Solves:** 6
**Description:**

> Time to pwn back, look for the malware on the compromised host!
> You must solve **Rick** first to be able to solve this challenge.
>
> **Hints:**
> - The goal is to retrieve credentials for C&C IRC channel from memory, do this by pwning the service on port 1337
> - Some people asked for the firewall rules on Roll:
>```
> *filter
> :INPUT DROP [56:3360]
> :FORWARD ACCEPT [0:0]
> :OUTPUT ACCEPT [997:167700]
> -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
> -A INPUT -p tcp -m tcp --dport 1234 -j ACCEPT
> -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
> -A INPUT -p tcp -m tcp --dport 80 -m limit --limit 1/sec --limit-burst 1 -j ACCEPT
> -A INPUT -p udp -j ACCEPT
> -A INPUT -p icmp -j ACCEPT
> COMMIT
>```
> - Debug build with more or less useful output available at the location of the old binary

## Write-up

(TODO)

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to rop_chain and includes references for learning rop_chain techniques.]