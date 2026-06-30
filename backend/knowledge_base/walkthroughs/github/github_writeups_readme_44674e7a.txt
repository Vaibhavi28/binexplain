---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/pico-ctf-2014/crypto/caesar-20/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Pico CTF 2014 : Caesar

**Category:** Crypto
**Points:** 20
**Description:**

>You find an encrypted message written on the documents. Can you decrypt it?

**Hint:**
>Is there a cipher named the same as the title of this problem?

## Write-up

We rotate the text using the caesar cipher using [this tool]():

```bash
$ for i in {0..25}; do python rot.py -l $i espdpncpealddascldptdfvaaychcjplgrehtnqxycvmykpblhr; done
espdpncpealddascldptdfvaaychcjplgrehtnqxycvmykpblhr
ftqeqodqfbmeebtdmequegwbbzdidkqmhsfiuoryzdwnzlqcmis
[...]
sgdrdbqdsozrrogqzrdhrtjoomqvqxdzufsvhbelmqjamydpzvf
thesecretpassphraseisukppnrwryeavgtwicfmnrkbnzeqawg
uiftfdsfuqbttqisbtfjtvlqqosxszfbwhuxjdgnoslcoafrbxh
[...]
```

The flag is `ukppnrwryeavgtwicfmnrkbnzeqawg`.

## Other write-ups and resources

* <http://ehsandev.com/pico2014/cryptography/caesar.html>
* <https://ctf-team.vulnhub.com/picoctf-2014-ceasar/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.