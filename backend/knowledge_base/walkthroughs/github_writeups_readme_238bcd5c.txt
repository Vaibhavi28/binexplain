---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pwnium-ctf-2014/usb-is-fun/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Easy
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Pwnium CTF 2014: USB if fun

**Category:** Forensics
**Points:** 100
**Description:**
> [http://41.231.53.40/for1.pcapng](for1.pcapng)

## Write-up

We have a packetdump containing USB(MS) packets. The first thing to do is always throw a `strings` and `grep` combination at a given file. Just in case.

```bash
$ strings -a for1.pcapng | grep -i Pwnium
Pwnium{408158c115a82175de37e8b3299d1f93}
```

Wuuaaat? Ok that is easy. Our flag is `Pwnium{408158c115a82175de37e8b3299d1f93}`.

## Other write-ups and resources

* <https://crazybulletctfwriteups.wordpress.com/2014/07/07/pwnium-ctf-2014-usb-so-fun/>
* <https://ctftime.org/writeup/1155>
* <http://krebsco.de/writeups/for1-usb-dump.html>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.