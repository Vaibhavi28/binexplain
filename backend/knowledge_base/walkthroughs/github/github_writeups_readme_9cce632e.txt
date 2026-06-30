---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/9447-ctf-2014/insanity_check/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# 9447 CTF 2014: insanity_check

**Category:** Reversing
**Points:** 1
**Solves:** 521
**Description:**

> Congrats, you can read!
>
> [`insanity`](insanity)

## Write-up

```bash
$ strings insanity | grep 9447
9447{This_is_a_flag}
```

The flag is `9447{This_is_a_flag}`.

## Other write-ups and resources

* <http://nandynarwhals.org/2014/12/02/9447-ctf-2014-insanity_check-reversing/>
* <http://theevilbit.blogspot.com/2014/12/9447-ctf-2014-writeup-reversing-125100.html>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.