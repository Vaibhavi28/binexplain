---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pwnium-ctf-2014/altered-code/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Pwnium CTF 2014: Altered code

**Category:** Stegano
**Points:** 150
**Description:**
> Our Spy got spotted in Japan, but before they catch him he send us this file. find out the secret code hidden in the code. [http://41.231.53.40/main.c](main.c)

## Write-up

Written by Tasteless for ctftime.org

> We got a C source code. If we look carefully at it we will notice that some 
lines are indented with tabs while others are indented with spaces.The solution 
is just to comment or delete the lines indented with tabs and execute the code 
to get the flag.

```Flag: D0nT_e4t_Sushi```

Source: https://ctftime.org/writeup/1177

## Other write-ups and resources

* <http://blog.dul.ac/2014/07/PWNIUM14/>
* <http://pastebin.com/kr6uDrN3>
* <https://crazybulletctfwriteups.wordpress.com/2014/07/08/pwnium-ctf-2014-alter-code/>
* <https://ctftime.org/writeup/1177>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.