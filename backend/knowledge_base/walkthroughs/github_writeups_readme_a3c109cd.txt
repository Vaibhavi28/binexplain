---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/master-challenge/hardcore-rop-200/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: rop_chain
DIFFICULTY: Hard
PROTECTIONS: NX, PIE
KEY_FUNCTIONS: gets, free
KEY_TECHNIQUE: The writeup describes a rop_chain vulnerability leveraging gets, free to hijack the control flow.
---
# Pico CTF 2014 : Hardcore ROP

**Category:** Master Challenge
**Points:** 200
**Description:**

>This program is obviously broken, but thanks to ASLR, PIE, and NX it's still pretty secure! Right?
NB: This problem is running in a slightly unusual setup to get extra PIE randomness. If you have an exploit that works 100% reliably locally (outside of GDB, which often disables any randomness), but you can't get it to land on our server, feel free to message us for help. [Source](hardcore_rop.c) [Binary](hardcore_rop)

>nc vuln2014.picoctf.com 4000

**Hint:**
>This is a statically linked binary (using musl libc). There is no full libc available for you to return into, but if you can leak a .text section address you can return into main(), randop(), and the chunks of libc that are included. Also, you'll probably need to hunt for ROP gadgets: here is a nice tool for that.

>[shell-storm.org](http://shell-storm.org/project/ROPgadget/)

## Write-up

(TODO)

## Other write-ups and resources

* <https://ctf-team.vulnhub.com/picoctf-2014-hardcore-rop/>
* <https://github.com/PizzaEaters/picoCTF-2014/tree/master/hardcore_rop>
* <http://barrebas.github.io/blog/2014/11/06/picoctf-hardcore-rop/>
* <https://www.whitehatters.academy/picoctf-hardcore-rop/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to rop_chain and includes references for learning rop_chain techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.