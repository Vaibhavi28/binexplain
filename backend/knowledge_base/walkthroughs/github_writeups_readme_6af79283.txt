---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/qiwi-ctf-2014/milk-road/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: other
DIFFICULTY: Unknown
PROTECTIONS: None
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a other vulnerability to hijack the control flow.
---
# Qiwi CTF 2014: Milk Road

**Category:** Web
**Points:** 150
**Author:** babayaga
**Description:**

> Capture the flag!
>
> <https://qiwictf2014.ru:16443/>

## Write-up

The URL in the description points to a web shop where you can register, log in, and buy items. The `/robots.txt` file reveals:

```
User-agent: *
Disallow: /templates/
```

Sure enough, <https://qiwictf2014.ru:16443/templates/> contains an open directory listing with six HTML templates. Let’s download them:

```bash
$ wget -r https://qiwictf2014.ru:16443/templates/
```

The templates are available in [the `templates` folder within this repository](templates). It looks like `shop.html` contains some conditional logic to display the flag:

```html
{% if flag %}
<h1>{{ flag }}</h1>
{% else %}
<tr>
<form method="post" action="">
<td>
<input type="hidden" name="item_id" value="31337">
<img src="/static/WMHlogoweb.gif" width="300px">
</td>
<td>$2048</td>
<td><input type="submit" value="Buy"></td>
</form>
</tr>
{% endif %}
```


https://qiwictf2014.ru:16443/templates/
https://qiwictf2014.ru:16443/templates/

(TODO)

## Other write-ups and resources

* none yet

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to other and includes references for learning other techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.