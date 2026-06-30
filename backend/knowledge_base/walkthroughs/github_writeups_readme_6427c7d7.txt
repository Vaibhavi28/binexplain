---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/ghost-in-the-shellcode-2014/rabbit-of-caerbannog/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: shellcode
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: However, you can get them by triggering an integer overflow.
---
# Ghost in the Shellcode 2014: Rabbit of Caerbannog

**Category:** Choose your Pwn Adventure 2
**Points:** 75
**Description:**

> Challenge available from within PwnAdventure2.

## Write-up

The challenge was to defeat a seemingly invincible rabbit.

Reading the code reveals that it can only be killed using a _Holy Hand Grenade_, an item that can only be traded for _89 gears_. Unfortunately, there is no legitimate way to get _gears_.

However, you can get them by triggering an integer overflow. Try to buy 999,999,999 Holy Hand Grenades at once, and this will give you lots of grenades and lots of gears, too.

The flag is `Thy_foe_b31ng_n4ughty_1n_My_s1ght_shall_snuff_it`.

## Other write-ups and resources

* <http://balidani.blogspot.com/2014/01/ghost-in-shellcode-2014-pwn-adventure-2.html>
* <http://tasteless.eu/2014/01/gits-2014-rabbit-of-caerbannog-pwn-adventure-75/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to shellcode and includes references for learning shellcode techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.