---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/rop-impossible/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: rop_chain
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a rop_chain vulnerability leveraging read to hijack the control flow.
---
# SECCON CTF 2014: ROP: Impossible

**Category:** Exploit
**Points:** 500
**Description:**

> ropi.pwn.seccon.jp:10000
>
> Read `/flag` and write the content to stdout, such as the following pseudo code.
>
> ```
> open("/flag", 0);
> read(3, buf, 32);
> write(1, buf, 32);
> ```
>
> Notice that the `vuln` executable is protected by an Intel Pin tool, the source code of which is `norop.cpp`.
>
> [`vuln`](vuln)
> [`norop.cpp`](norop.cpp)
> [`norop_conf`](norop_conf)

## Write-up

(TODO)

## Other write-ups and resources

* <https://rzhou.org/~ricky/seccon2014/rop_impossible/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to rop_chain and includes references for learning rop_chain techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.