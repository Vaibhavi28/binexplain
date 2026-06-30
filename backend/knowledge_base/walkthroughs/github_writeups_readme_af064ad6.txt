---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/tinyctf-2014/valet/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Easy
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# tinyCTF 2014: Valet!

**Category:** Exploitable
**Points:** 300
**Description:**

> [Exploit this](pwn300.zip)
> Over here: `nc 54.69.118.120 7000`

## Write-up

```bash
$ unzip pwn300.zip
Archive:  pwn300.zip
  inflating: pwn300

$ file pwn300
pwn300: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, not stripped
```

`pwn300` accepts a `port` argument and starts a service listening on that port. To run it locally, use:

```bash
$ ./pwn300 9001
```

In another window/tab, you can then connect to the service:

```bash
$ nc localhost 9001
Welcome to Google Gamble.
=========================

Google Gamble is easy. Guess the card drawn
from the deck and double your money! Make it all
the way to $1048576 to get a flag! Good luck!

Your current balance: 1$

Select an option:
1. Guess a card
2. Get the flag
3. Quit
```

(TODO)

## Other write-ups and resources

* <https://github.com/jesstess/tinyctf/blob/master/valet/valet.md>
* <http://barrebas.github.io/blog/2014/10/03/tinyctf/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.