---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/ghost-in-the-shellcode-2014/moon-boots/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: shellcode
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a shellcode vulnerability to hijack the control flow.
---
# Ghost in the Shellcode 2014: Moon Boots

**Category:** Choose your Pwn Adventure 2
**Points:** 50
**Description:**

> Challenge available from within PwnAdventure2.

## Write-up

The challenge was to enter the Moon level somehow.

This can be done in several ways:

1. by hacking the gravity modifier, changing it from `-9.81` to, say, `0.5`
2. by hacking the initial jump velocity modifier, changing it to a value higher than `25`

That way, it’s possible to jump out of bounds on the regular map, which effectively teleports you to the moon.

The flag is `Use a Tab, Space will leave you breathless`.

## Other write-ups and resources

* <http://balidani.blogspot.com/2014/01/ghost-in-shellcode-2014-pwn-adventure-2.html>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to shellcode and includes references for learning shellcode techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.