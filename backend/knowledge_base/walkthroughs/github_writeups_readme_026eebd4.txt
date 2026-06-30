---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/tinyctf-2014/can-has-stdio/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# tinyCTF 2014: CAN HAS STDIO?

**Category:** Miscellaneous
**Points:** 50
**Description:**

> [Download file](misc50.zip)

## Write-up

Let’s unzip the provided `misc50.zip` file:

```bash
$ unzip misc50.zip
Archive:  misc50.zip
  inflating: misc50
```

The extracted `misc50` file is a [brainfuck](https://en.wikipedia.org/wiki/Brainfuck) program. When executed, it prints the flag:

```
flag{esolangs_for_fun_and_profit}
```

## Other write-ups and resources

* <https://github.com/evanowe/TinyCTF2014-writeups/blob/master/README.md#can-has-stdio>
* <https://github.com/jesstess/tinyctf/blob/master/stdio/stdio.md>
* <http://barrebas.github.io/blog/2014/10/03/tinyctf/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.