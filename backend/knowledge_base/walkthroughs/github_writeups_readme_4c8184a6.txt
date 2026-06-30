---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/su-ctf-quals-2014/what_is_this/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# Sharif University Quals CTF 2014: What is this

**Category:** Steganography
**Points:** 20
**Solves** 308
**Description:**

> Find the flag!
>
> [Download](what-is-this.tar.gz)

## Write-up

We are given two pictures:

![](pic1.jpg)
![](pic2.jpg)

Using a stegonagraphy tool like [stegsolve](http://www.wechall.net/forum/show/thread/527/Stegsolve\_1.3/page-1), we combine both pictures by XORing them. The result is this picture, containing the `AZADI TOWER` flag:

![](azaditower.png)

## Other write-ups and resources

* <http://ctf.sharif.edu/2014/quals/su-ctf/write-ups/11/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.