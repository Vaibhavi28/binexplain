---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/ghost-in-the-shellcode-2014/cave-of-nope/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: shellcode
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a shellcode vulnerability to hijack the control flow.
---
# Ghost in the Shellcode 2014: Cave of Nope

**Category:** Choose your Pwn Adventure 2
**Points:** 50
**Description:**

> Challenge available from within PwnAdventure2.

## Write-up

The challenge was to enter the area called ‘Creepy Cave’, bridge a huge gap somehow, and then defeat the Spider Queen.

Crossing the gap can only be done after hacking the game files and increasing the player’s running speed or the jump velocity, for example.

To avoid getting killed by the Spider Queen, you could hack the _Wine_ item modifier, so that drinking wine makes you invulnerable (instead of just slightly boosting your damage resistance).

The flag is `At least it wasnt full of Creepers`.

## Other write-ups and resources

* <http://balidani.blogspot.com/2014/01/ghost-in-shellcode-2014-pwn-adventure-2.html>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to shellcode and includes references for learning shellcode techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.