---
SOURCE: github_writeups
URL: https://raw.githubusercontent.com/ctfs/writeups/master/seccon-ctf-2014/jspuzzle/README.md
CHALLENGE: README
EVENT: GitHub - ctfs/writeups
TEAM: N/A
CATEGORY: rop_chain
DIFFICULTY: Unknown
PROTECTIONS: PIE
KEY_FUNCTIONS: None
KEY_TECHNIQUE: The writeup describes a rop_chain vulnerability to hijack the control flow.
---
# SECCON CTF 2014: jspuzzle

**Category:** Web
**Points:** 100
**Description:**

> [`jspuzzle.zip`](https://github.com/ctfs/write-ups/tree/master/seccon-ctf-2014/challenge)
>
> You need to fill in all the blanks!

## Write-up

[The extracted contents of the provided ZIP file are available in the `challenge` directory.](https://github.com/ctfs/write-ups/tree/master/seccon-ctf-2014/challenge)

The `q.html` document contains a puzzle with a drag-and-drop interface. The goal is to construct valid JavaScript that executes `alert(1)` using nothing but the provided pieces. The SHA-1 hash of the expected solution is the flag.

The puzzle solution is:

```js
"use strict";

({ "function" : function() {
  this[ "null" ] = (new Function( "return" + "/*^_^*/" + "this" ))();
  var pattern = "^[w]$";
  var r = new RegExp( pattern );
  this[ r[ "exec" ]( pattern ) ][ "alert" ]( 1 );
}})[ "Function" [ "toLowerCase" ]() ]();
```

The corresponding SHA hash is `SECCON{3678cbe0171c8517abeab9d20786a7390ffb602d}`.

## Other write-ups and resources

* <http://tasteless.eu/2014/12/seccon-ctf-2014-online-qualifications-jspuzzle/>
* [Portuguese](https://ctf-br.org/wiki/seccon/seccon2014/w100-jspuzzle/)

[Additional Context: This documentation page explains the details of README in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to rop_chain and includes references for learning rop_chain techniques.] This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals. This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals.