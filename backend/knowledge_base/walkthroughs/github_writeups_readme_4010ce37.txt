---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/reverse-it/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# SECCON CTF 2014: Reverse it

**Category:** Binary
**Points:** 100
**Description:**

> [`Reverseit`](Reverseit)

## Write-up

Let’s take the challenge name literally and reverse the hexadecimal representation of the bytes in the file:

```bash
$ xxd -p Reverseit | tr -d '\n' | rev | xxd -r -p > reversed

$ file reversed
reversed: JPEG image data, JFIF standard 1.01
```

The result is a JPEG image that displays a horizontally flipped (“reversed”) version of the flag:

![](reversed.jpg)

The flag is `SECCON{6in\_tex7}`.

## Other write-ups and resources

* <http://tasteless.eu/2014/12/seccon-ctf-2014-online-qualifications-reverseit-writeup/>
* <http://blogs.univ-poitiers.fr/e-laize/2014/12/07/seccon-2014-reverseit/>
* [Indonesian](http://www.hasnydes.us/2014/12/reverseit-binary-seccon-ctf-100pts/)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.