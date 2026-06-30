---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/quest-100/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# D-CTF 2014: Quest 100 – Warm Up

**Category:** Quest
**Points:** 100
**Description:**

> My password is password but it is `2_*_10_*_16_*_8_*_4` characters long. Whats my password ? Ha ha ha!

## Write-up

The answer was the MD5 hash of the string `password`, i.e.:

```bash
$ md5 -s password
MD5 ("password") = 5f4dcc3b5aa765d61d8327deb882cf99
```

Explanation:

* `2*4 = 8` = number of bytes in the string `password`
* `10*16-8*2 = 128` = number of bits in an MD5 hash
* `4*8 = 32 = 16*2` = number of bytes in the hexadecimal representation of an MD5 hash

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.