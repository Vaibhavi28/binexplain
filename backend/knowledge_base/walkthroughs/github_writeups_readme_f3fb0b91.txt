---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/binary-exploitation/what-the-flag-140/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: gets, read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging gets, read to hijack the control flow.
---
# Pico CTF 2014 : What the Flag

**Category:** Binary Exploitation
**Points:** 140
**Description:**

>This binary uses stack cookies to prevent exploitation, but all hope is not lost. Read the flag from flag.txt anyways! The binary can be found at /home/what_the_flag/ on the shell server. You can solve this problem interactively [here](https://picoctf.com/problem-static/binary/WhatTheFlag/what_the_flag.html
). The source can be found [here](what_the_flag.c).

**Hint:**
>How can you enter a correct password, but still overflow the buffer? Think about what terminates gets(). Also, the file name that you want to open is already in the binary!

## Write-up

(TODO)

## Other write-ups and resources

* <https://ctf-team.vulnhub.com/picoctf-2014-what-the-flag/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.