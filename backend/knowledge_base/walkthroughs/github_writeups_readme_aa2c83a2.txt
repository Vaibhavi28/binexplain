---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/binary-exploitation/never-note-180/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: Canary
KEY_FUNCTIONS: malloc, read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging malloc, read to hijack the control flow.
---
# Pico CTF 2014 : Never note

**Category:** Binary Exploitation
**Points:** 180
**Description:**

>In light of the recent attacks on their machines, Daedalus Corp has implemented a buffer overflow detection library. Nevernote, a program made for Daedalus Corps employees to take notes, uses this library.
Can you bypass their protection and read the secret? The binary can be found at /home/nevernote/ on the shell server.

The source can be downloaded here.

**Hint:**
>Think about what fields of the canary struct you control. Also, malloc() is predictable without ASLR.

## Write-up

(TODO)

## Other write-ups and resources

* <http://cregnec.github.io/blog/2014/11/17/picoctf-2014-writeup.html#nevernote>
* <https://ctf-team.vulnhub.com/picoctf-2014-nevernote/>
* <https://github.com/PizzaEaters/picoCTF-2014/tree/master/nevernote>
* <http://barrebas.github.io/blog/2014/11/06/picoctf-write-ups/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.