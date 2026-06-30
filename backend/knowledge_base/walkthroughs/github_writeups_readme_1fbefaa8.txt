---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/asis-ctf-finals-2014/caplow/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# ASIS Cyber Security Contest Finals 2014: CapLow

**Category:** Crypto
**Points:** 75
**Description:**

> Find the flag
> Our new agent encrypt a message like this, let us know what he wanted to say!
> `qvnju181mjziote0zge4mdk0odi4odfmnmnmnmi5zjm2yzy3mq==`

## Write-up

The `==` at the end of the provided ciphertext hints at base64 encoding… But it doesn’t decode to anything useful:

```bash
$ base64 --decode <<< 'qvnju181mjziote0zge4mdk0odi4odfmnmnmnmi5zjm2yzy3mq=='
���_5�<�״����4�ظ���i�h��9��<��
```

It’s a little uncommon for a base64-encoded string to be completely in lowercase like that. Let’s try uppercasing the first few characters:

```bash
$ base64 --decode <<< 'QVNJU181mjziote0zge4mdk0odi4odfmnmnmnmi5zjm2yzy3mq=='
ASIS_5�<�״����4�ظ���i�h��9��<��
```

Aha! That looks like the start of a flag. Let’s continue to uppercase characters one by one, reverting to lowercase only if the change makes the output look worse instead of better. Eventually we end up with `QVNJU181MjZiOTE0ZGE4MDk0ODI4ODFmNmNmNmI5ZjM2YzY3MQ==`:

```bash
$ base64 --decode <<< 'QVNJU181MjZiOTE0ZGE4MDk0ODI4ODFmNmNmNmI5ZjM2YzY3MQ=='
ASIS_526b914da809482881f6cf6b9f36c671
```

The flag is `ASIS_526b914da809482881f6cf6b9f36c671`.

## Other write-ups and resources

* <http://www.mrt-prodz.com/blog/view/2014/10/asis-ctf-finals-2014---caplow-75pts-writeup>
* <https://beagleharrier.wordpress.com/2014/10/13/asis-ctf-finals-2014caplow-writeup/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.