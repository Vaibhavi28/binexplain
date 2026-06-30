---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/misc-100/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: free
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging free to hijack the control flow.
---
# D-CTF 2014: Misc 100 – SE FTW

**Category:** Misc
**Points:** 100
**Description:**

> In two words describe social engineering!
>
> **Hint:** 2f722f6e6574736563

## Write-up

Since the hint consists of hexadecimal digits only, let’s try to decode it:

```bash
$ xxd -r -p <<< 2f722f6e6574736563
/r/netsec
```

[/r/netsec](https://www.reddit.com/r/netsec) is a subreddit where information security news is discussed. In its sidebar contains a bunch of links, including this one:

> /r/SocialEngineering - Free Candy

The flag is `free candy`.

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.