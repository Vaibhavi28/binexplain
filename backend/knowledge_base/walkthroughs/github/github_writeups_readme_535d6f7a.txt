---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/asis-ctf-finals-2014/antenna/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: NX
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# ASIS Cyber Security Contest Finals 2014: Antenna

**Category:** Reverse, PPC
**Points:** 200
**Description:**

> Download [this](antena_bffb7c0bfe9d5eac2e1364ce7ceb995e) file and find the flag.

## Write-up

Let’s see what [the provided file](antena_bffb7c0bfe9d5eac2e1364ce7ceb995e) could be:

```bash
$ file antena_bffb7c0bfe9d5eac2e1364ce7ceb995e
antena_bffb7c0bfe9d5eac2e1364ce7ceb995e: xz compressed data
```

So, we extract the file using the built-in `xz` or `unxz` commands:

* `xz -dc < antena_bffb7c0bfe9d5eac2e1364ce7ceb995e > antenna`
* `unxz < antena_bffb7c0bfe9d5eac2e1364ce7ceb995e > antenna`

Alternatively, extract the provided file using [p7zip](http://p7zip.sourceforge.net/):

```bash
7z x antena_bffb7c0bfe9d5eac2e1364ce7ceb995e
```

Let’s find out what the extracted file is:

```bash
$ file antenna
antenna: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, stripped
```

(TODO)

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.