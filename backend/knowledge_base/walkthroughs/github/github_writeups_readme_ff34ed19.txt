---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/su-ctf-quals-2014/hear_with_your_eyes/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Sharif University Quals CTF 2014: Hear with your Eyes

**Category:** Steganography
**Points:** 100
**Solves** 172
**Description:**

> Hear With Your Eyes
>
> [Download](sound.wav.tar.gz)

## Write-up

We are given a WAVE audio file, `sound.wav`:

```
$ file sound.wav
sound.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz
```

The title says to "hear with your eyes", so we use audacity to look at the spectrum of frequencies in that file using the `spectogram` feature.

![](audacity_specto.png)

And we get the flag `e5353bb7b57578bd4da1c898a8e2d767`:

![](flag.png)

## Other write-ups and resources

* <http://ctf.sharif.edu/2014/quals/su-ctf/write-ups/19/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.