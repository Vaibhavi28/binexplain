---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/csaw-ctf-2014/fuzyll/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# CSAW CTF 2014: Fuzyll

**Category:** Recon
**Points:** 100
**Description:**

> Unbeknownst to many, Fuzyll is actually the next Dendi. Like most of Reddit, he just needs better teammates first. He's not ranked yet, but his MMR would definitely be at least 10000. I mean, have you seen him play?
>
> Written by fuzyll

## Write-up

One possible solution is:

1. Go to [dotabuff.com](http://www.dotabuff.com/).
2. Search for ‘fuzyll’ and click ‘matches’ which takes you to <http://www.dotabuff.com/players/80484382/matches>.
3. Click the seventh match (at the time of CSAW CTF) where it says “Won Match”.
4. The URL is <http://www.dotabuff.com/matches/903461176>, so the match ID is `903461176`.
5. Go to [dotabank.com](http://dotabank.com/)
6. Enter the match ID `903461176`, which takes you to <http://dotabank.com/replays/903461176/>.
7. Get the replay and get the flag.

## Other write-ups and resources

* <http://www.incertia.net/blog/csaw-ctf-quals-2014-fuzyll/>

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.