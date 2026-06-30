---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/csaw-ctf-2014/big-data/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# CSAW CTF 2014: Big Data

**Category:** Networking
**Points:** 100
**Description:**

> Something, something, data, something, something, big
>
> Written by HockeyInJune
>
> [pcap.pcapng](pcap.pcapng)

## Write-up

Open [the provided `pcap.pcapng` file](pcap.pcapng) in Wireshark. Go to _Edit_ → _Find Packet_ → _String_ → _Search in packet bytes_, and enter `password`.

![](search.png)

This reveals an exchange over the `telnet` protocol where a server asks for a password. The next packets each contain a single character of the password, sent from the client to the server. To quickly view them all, right-click on the first packet and click _Follow TCP Stream_.

![](tcp-stream.png)

This reveals the following:

```
Linux 3.13.0-32-generic (ubuntu) (pts/0)

..ubuntu login: j.ju.ul.li.ia.an.n
.
..Password: flag{bigdataisaproblemnotasolution}
.
.
Login incorrect
..ubuntu login:
```

The flag is `bigdataisaproblemnotasolution`.

## Other write-ups and resources

* <http://evandrix.github.io/ctf/2014-csaw-networking-100-bigdata.html>
* <http://shankaraman.wordpress.com/2014/09/22/csaw-ctf-2014-networking-100-bigdata-writeup/>
* <http://bt3gl.github.io/csaw-ctf-2014-networking-100-big-data.html>
* <https://ucs.fbi.h-da.de/writeup-csaw-big-data/>
* <http://www.incertia.net/blog/csaw-ctf-quals-2014-big-data/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.