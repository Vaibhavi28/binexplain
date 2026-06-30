---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/hitcon-ctf-2014/mid/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# HITCON CTF 2014: mid

**Category:** ACM
**Points:** 250
**Description:**

> Problem A
>
> http://54.64.29.164:32384/

**Hint:**

> gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1)
> gcc -O2 -static source.c
> Read input from stdin and write output to stdout.
> Single test case in each file, but test several times on multiple file.
>
> It's a CTF challange, you may need a interesting trick to solve it.
> Both setrlimit & cgroup is used.
> (memory.limit_in_bytes, memory.swappiness, RLIMIT_AS)
>
> No temp file is allowed. In fact, it's chroot to an read-only empty directory.
> No socket, IPC, so you can't send the test data out.
> Number of process limit to 8.
> All syscall is allowed.
>
> You need to STEAL MORE MEMORY, but how? where?

## Write-up

(TODO)

## Other write-ups and resources

* <http://puu.sh/aXd9p/44f33626e7.txt>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.