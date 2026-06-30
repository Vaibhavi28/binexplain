---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/binary-exploitation/this-is-endian-40/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: system
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging system to hijack the control flow.
---
# Pico CTF 2014 : This is the Endian

**Category:** Binary Exploitation
**Points:** 40
**Description:**

>This is the end! Solving this challenge will help you defeat Daedalus's cyborg. You can find more information about endianness and the problem [here](https://picoctf.com/problem-static/binary/this-is-the-endian/endian.html#1). The flag is the smallest possible program input that causes the program to print "Access Granted".

**Hint:**
>Integers are 4 bytes (characters) long.

## Write-up
Looking through the source code we can see that the program looks for the first four chars of the access code to be hex 0x52657663 and the 2nd four chars to be 0x30646521. Unfortunately when we translate those two halfs to ASCII and put them together it is not accpeted as the answer. This means that the system is a little endian system. Flipping 0x52657663 to 0x63766552 and 0x030646521 to 0x21656430 gives us the answer.

## Answer
cveR!ed0

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.