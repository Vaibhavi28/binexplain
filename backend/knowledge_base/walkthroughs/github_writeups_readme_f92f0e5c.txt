---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/31c3-ctf-2014/signals/safelock/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# 31C3 CTF 2014: safelock

**Category:** signals
**Points:** 20
**Solves:** 2
**Description:**

> This is the circuit of a safe lock. Get the key to open it! <http://188.40.18.86/safelock/>
> It’s neither about webtronics nor ngspice. Disregard bugs in both.
> If you want to write spice code directly, use something like this:
>
> ```bash
> cat test.cir | curl --data-binary '@-' http://188.40.18.86/safelock/contest_spice/spice.cgi
> ```
>
> **Hints:**
>
> - when you hand-build your SPICE code: keep in mind that the first line is special and should be a comment, otherwise it is ignored.
> - The web interface does fully work with Chrome. Use Firefox.

## Write-up

(TODO)

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.