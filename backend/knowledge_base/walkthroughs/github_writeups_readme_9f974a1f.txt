---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/network-100/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# D-CTF 2014: Network 100 – PCT

**Category:** Network
**Points:** 100
**Description:**

> My manager lives at 10.13.37.21. Any guest is always welcome. But he has a secret. Can you find it out?

## Write-up

The following solution involves some random guessing, hunches, and curiosity.

The statement “Any guest is always welcome” is a hint about a guest or public account of perhaps a user account.

After testing some combinations of `username: guest` and `password: <blank>` or `welcome ` or `guest` to the login form that’s displayed when you open `http://10.13.37.21/` from a web browser, we switched to testing it for SSH login. We ran `ssh guest@10.13.37.21` and it seems that an SSH daemon is actually up. After a few connection attempts, we discovered that the password is also `guest`.

Navigating and listing the directory of `/var/www` revealed an `html` folder, and `ls /var/www/html` reveals some folders and an `index.php` file. Running `cat /var/www/html/index.php` reveals some interesting PHP code at the top of the file.

One line reads:

> The secret is behind 0f388689dc4728cfde0de9a1ee47c8d3 :)

Googling `0f388689dc4728cfde0de9a1ee47c8d3` reveals that it is the MD5 hash of the string `ididyourmom`, which is the flag.

## Other write-ups and resources

* <http://www.mrt-prodz.com/blog/view/2014/10/defcamp-ctf-quals-2014---network-100--pct-100pts-writeup/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.]