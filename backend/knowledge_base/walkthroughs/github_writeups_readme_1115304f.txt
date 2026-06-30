---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/decrypt-it-easy/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Easy
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# SECCON CTF 2014: Decrypt it (Easy)

**Category:** Crypto
**Points:** 200
**Description:**

> [`crypt1.zip`](crypt1.zip)

## Write-up

(TODO)

```bash
$ unzip crypt1.zip
Archive:  crypt1.zip
  inflating: ecrypt1.bin
  inflating: rnd
  inflating: readme.txt

$ cat readme.txt
./rnd crypt1.png ecrypt1.bin

$ file rnd
rnd: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
```

## Other write-ups and resources

* <http://tasteless.eu/2014/12/seccon-quals-2014-decrypt-it-easy-crypto200/>
* <http://blogs.univ-poitiers.fr/e-laize/2014/12/08/seccon-2014-quals-crypto-decrypt-it/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.