---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/rea-juu-watch/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# SECCON CTF 2014: REA-JUU WATCH

**Category:** Web
**Points:** 200
**Description:**

> <http://reajuu.pwn.seccon.jp/>

## Write-up

The URL points to a quiz website. After creating a new account and logging in, it poses six multiple-choice-style questions, one after the other. After answering these we end up at the URL <http://reajuu.pwn.seccon.jp/quiz/7> which displays “Game over” as well as our total score. By inspecting the network traffic while opening that last page, we note an Ajax request to <http://reajuu.pwn.seccon.jp/users/chk/13337> where `13337` is our user account ID. The response body contains the username, password, and the total score for that user, all in plain text:

```bash
$ curl http://reajuu.pwn.seccon.jp/users/chk/13337
{"username":"h1j9fgul","password":"fo1xe2mk","point":0}
```

Let’s see what happens if we request the data for user with ID `1`:

```bash
$ curl http://reajuu.pwn.seccon.jp/users/chk/1
{"username":"rea-juu","password":"way_t0_f1ag","point":99999}
```

After logging in on <http://reajuu.pwn.seccon.jp/> with username `rea-juu` and password `way\_t0\_f1ag` and finishing the quiz, the flag is revealed: `SECCON{REA\_JUU\_Ji8A\_NYAN}`.

## Other write-ups and resources

* <https://github.com/S42X/CTF/blob/master/SECCON/ReaJuuWatch.md>
* [Portuguese](https://ctf-br.org/wiki/seccon/seccon2014/w200-rea-juu-watch/)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.