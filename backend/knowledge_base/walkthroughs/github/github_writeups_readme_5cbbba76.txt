---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/plaid-ctf-2014/multiplication-is-hard/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Hard
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Plaid CTF 2014: multiplication is hard

**Category:** Misc
**Points:** 10
**Description:**

> The Plague went back in time... but we haven't yet figured out what he did this time... Anyway, what is 38.55 * 1700?

## Write-up

Mathematically, `38.55 * 1700 = 65535` but that solution was not accepted.

Years ago (“back in time”), [Excel used to have a bug](http://blogs.office.com/2007/09/25/calculation-issue-update/) where calculations that resulted in a number close to 65,535 would instead show a result of 100,000.

The flag is `100000`.

## Other write-ups and resources

* <https://github.com/hackerclub/writeups/blob/master/plaidctf-2014/multiplication-is-hard/WRITEUP-pipecork.md>
* <http://csrc.tamuc.edu/css/?p=152>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.