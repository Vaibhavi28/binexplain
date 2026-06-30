---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/olympic-ctf-2014/just-no-one/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# Olympic CTF 2014: Just No One

**Category:** Binathlon (Bin)
**Points:** 10
**Author:** vos
**Description:**

> Here’s your binary: [`setup.exe`](setup.exe)

## Write-up

The provided `setup.exe` file is a standard installation wizard.

![](setup-1.png)

As usual with these wizards, the second screen contains a very long license agreement that must be accepted before continuing the installation.

![](setup-2.png)

The next screen prompts for a password. Which password? Hmm… It’s possible to [crack it](http://maroueneboubakri.blogspot.com/2014/02/olympic-ctf-sochi-2014-binathlon-10.html) and then proceed with the installation, but that doesn’t really help, because when the executable is opened, it just repeats “You already saw the flag.”:

![You already saw the flag.](executable.png)

And indeed — after running `setup.exe` again and carefully reading the license agreement this time, we notice something unusual:

![7A. YOU MAY SUBMIT THIS TO GET TEN POINTS: ILOVEREADINGEULAS.](setup-4.png)

The flag is `ILOVEREADINGEULAS`.

## Other write-ups and resources

* <http://maroueneboubakri.blogspot.com/2014/02/olympic-ctf-sochi-2014-binathlon-10.html>
* <https://ctftime.org/writeup/926>
* <http://cybersecurity.cci.fsu.edu/olympic-ctf-2014-writeup/>
* <http://delimitry.blogspot.ru/2014/02/olympic-ctf-2014-writeups.html>
* <http://ctfwriteups.blogspot.jp/2014/02/olympic-ctf-2014-binathlon-10-just-no.html>
* [Chinese](http://ddaa.logdown.com/posts/178446-olympic-ctf-2014-10-point-summary)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.