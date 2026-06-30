---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/crypto/web-interseption-140/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Pico CTF 2014 : Web Instresption

**Category:** Crypto
**Points:** 140
**Description:**

>We were able to get some code running in a Daedalus browser. Unfortunately we can't quite get it to send us a cookie for its internal login page ourselves... But we can make it make requests that we can see, and it seems to be encrypting using ECB mode. See here for more details about what we can get. It's running at [vuln2014.picoctf.com:65414](http://vuln2014.picoctf.com:65414). Can you get us the cookie?

**Hint:**
>In ECB mode, the same plaintext block appearing in two different places leads to the same ciphertext block appearing in both places. Can you figure out how to use this, and the encryption oracle that you have, to decrypt the cookies one byte at a time?

## Write-up

(TODO)

## Other write-ups and resources

* <http://ehsandev.com/pico2014/cryptography/web_interception.html>
* <https://ctf-team.vulnhub.com/picoctf-2014-web-interception/>
* <http://barrebas.github.io/blog/2014/11/06/picoctf-write-ups/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.