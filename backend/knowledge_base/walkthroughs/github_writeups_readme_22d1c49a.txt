---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/csaw-ctf-2014/greenhornd/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: shellcode
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a shellcode vulnerability to hijack the control flow.
---
# CSAW CTF 2014: greenhornd

**Category:** Exploitation
**Points:** 400
**Description:**

> ```bash
> nc 54.164.253.42 9998
> ```
>
> This is one of those "key" challenges we talked about on the stream. Also, you should just CreateFile and WriteFile to stdout for your shellcode. Anything more complicated is probably blocked by the App Container.
>
> Update: You can use AppJailLauncher to launch `greenhornd.exe` just like the game server does with:
>
> ```
> AppJailLauncher.exe /network /key:key /port:9998 /timeout:30 greenhornd.exe
> ```
>
> Written by RyanWithZombies
>
> [greenhornd.exe](greenhornd.exe)
> [AppJailLauncher.exe](AppJailLauncher.exe)

## Write-up

(TODO)

## Other write-ups and resources

* <https://hackucf.org/blog/csaw-2014-exploitation-400-greenhornd-exe/>
* <https://gist.github.com/g05u/221b61d13804c5fd87d0>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to shellcode and includes references for learning shellcode techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.