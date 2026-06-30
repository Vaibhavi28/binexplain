---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/defkthon-ctf/recon-100/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# DEFKTHON CTF: Recon 100

**Description:**

> [Francis Alexander](https://www.google.co.in/#q=Francis+Alexander)

## Write-up

Francis Alexander is a programmer who works for Opensec. He has a GitHub account: <https://github.com/torque59> This account has <http://wiredcreation.blogspot.in/> set as the website for this user.

The flag is hidden on <http://wiredcreation.blogspot.in/2014/02/nosql-exploitation-framwework-released.html>. Inspect the DOM using your browser’s developer tools to look for HTML comments (note: plain view-source won’t work as the content is loaded through Ajax). You’ll eventually see this:

```html
<!-- flag{hmm_try_nosql_dbs_dude}-->
```

The flag is `hmm_try_nosql_dbs_dude`.

## Other write-ups and resources

* <http://ctfwriteups.blogspot.in/2014/03/defkthon2014-recon-100.html>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.