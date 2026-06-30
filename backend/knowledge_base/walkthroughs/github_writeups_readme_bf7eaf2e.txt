---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/csaw-ctf-2014/bo/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Easy
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# CSAW CTF 2014: bo

**Category:** Exploitation
**Points:** 100
**Description:**

> exploit this
>
> ```bash
> nc 54.165.176.104 1515
> ```
>
> Written by HockeyInJune
>
> [bo](bo)

## Write-up

[The provided `bo` file](bo) is an ELF executable:

```bash
$ file bo
bo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, not stripped
```

This may not be the intended solution, but simply looking for ASCII strings in the binary reveals the flag:

```bash
$ strings bo | grep 'flag'
flag{exploitation_is_easy!}
```

Alternatively, you could open the file in [IDA](https://www.hex-rays.com/products/ida/support/download.shtml) (which is what the challenge actually suggests if you run it) and click _View_ → _Open Subviews_ → _Strings_.

The flag is `exploitation_is_easy!`.

## Other write-ups and resources

* <http://www.mrt-prodz.com/blog/view/2014/09/csaw-ctf-quals-2014---bo-100pts-writeup>
* <http://evandrix.github.io/ctf/2014-csaw-exploitation-100-bo.html>
* <https://ucs.fbi.h-da.de/writeup-csaw-bo/>
* <http://www.incertia.net/blog/csaw-ctf-quals-2014-bo/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.