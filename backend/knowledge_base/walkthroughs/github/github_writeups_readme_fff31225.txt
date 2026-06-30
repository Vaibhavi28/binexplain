---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/ncn-ctf-2014/MoonKV/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# NoConName 2014 Finals: MoonKV

**Category:** Misc
**Points:** ???
**Description:**

Can you see the flag?

## Write-up

We are given a .mkv video, upon examination there is an alternate audio track. Extracting this track reveals a digitally encoded image using SSTV. Using any SSTV decoding software reveals a picture of the moon landing, at the bottom of the image is the flag in red letters.

Caveat: the audio track is about 10 seconds longer than the video, so if the video processing software you're using is bad, it may get truncated. Since the flag is written at the bottom of the image, truncating the last seconds effectively removes the flag.

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.