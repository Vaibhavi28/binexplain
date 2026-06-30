---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/decrypt-it-hard/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Hard
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# SECCON CTF 2014: Decrypt it (Hard)

**Category:** Crypto
**Points:** 300
**Description:**

> ```
> g^k=69219086192344
> 20<k<20000
> ```
>
> [`c2.zip`](c2.zip)

## Write-up

(TODO)

```bash
$ unzip c2.zip
Archive:  c2.zip
   creating: crypt2/
  inflating: crypt2/E
  inflating: crypt2/eflag.bin
  inflating: crypt2/readme.txt

$ cat crypt2/readme.txt
./E 1 69219086192344 flag.png eflag.bin

$ file crypt2/E
crypt2/E: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
```

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.