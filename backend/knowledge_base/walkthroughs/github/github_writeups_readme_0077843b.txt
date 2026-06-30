---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/ghost-in-the-shellcode-2014/pillowtalk/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: shellcode
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: system
KEY_TECHNIQUE: The writeup describes a shellcode vulnerability leveraging system to hijack the control flow.
---
# Ghost in the Shellcode 2014: Pillowtalk

**Category:** Crypto
**Points:** 200
**Description:**

> Find the key! [File](https://2014.ghostintheshellcode.com/pillowtalk-a692e2669fa69d57870e55608888f02303d35ca3).

## Write-up

The headers of the provided `pillowtalk-a692e2669fa69d57870e55608888f02303d35ca3` file contain `7zXZ`, indicating it’s `xz`-compressed data.

So, extract the provided file using [p7zip](http://p7zip.sourceforge.net/):

```bash
7z x pillowtalk-a692e2669fa69d57870e55608888f02303d35ca3
```

Then, … (TODO)

The flag is `WhyDoFartsSmell?SoTheDeafCanEnjoyThemAlso`.

## Other write-ups and resources

* <https://systemoverlord.com/blog/2014/01/19/ghost-in-the-shellcode-2014-pillowtalk/>
* <http://broot.ca/gitsctf-pillowtalk-crypto-200>
* <https://www.youtube.com/watch?v=G50typU3mLg>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to shellcode and includes references for learning shellcode techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.