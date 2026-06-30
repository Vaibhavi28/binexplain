---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/su-ctf-quals-2014/huge_key/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Sharif University Quals CTF 2014: Huge Key

**Category:** Cryptography
**Points:** 100
**Solves** 119
**Description:**

> Find the flag.
>
> [Download](hugekey.tar.gz)

## Write-up

We are given two files, a `ciphertxt.bin` and a php file `encipher.php`:

[encipher.php](encipher.php)

It uses a key and a random generated IV to encrypt the contents of the unknown file `flag.txt` with the `MCRYPT_RIJNDAEL_128` cipher, also known as the `AES` cipher.

The author of this php file tries to load a 128 bit key by XORing the bytes of `key` with the contents of an unknown file `hugekey.bin`, however (s)he only sets the first two bytes of `key`.

Therefore we can bruteforce the cleartext by decrypting `ciphertext.bin` with the AES cipher using all 65536 possible combinations of this key.

The following code decrypts `ciphertext.bin` and prints all cleartexts matching the substring `flag`:

[rijndael.py](rijndael.py)

Executing it reveals our flag:

```bash
$ python rijndael.py ciphertext.bin
the flag is e3565503fb4be929a214a9e719830d4e
```

Looks like our flag is `e3565503fb4be929a214a9e719830d4e`.
## Other write-ups and resources

* <http://ctf.sharif.edu/2014/quals/su-ctf/write-ups/21/>
* [Vietnamese](https://13c5.wordpress.com/2014/09/28/su-ctf-quals-2014-huge-key/)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.]