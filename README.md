# Hash Identifier & Dictionary Cracker

**Project 06** of a pentest/red-team learning portfolio — see the [full roadmap](../ROADMAP.md).

Two small tools in one file: guess what algorithm produced a given hash
just from its shape, and — for the algorithms Python's `hashlib` can
compute directly — dictionary-attack it against a wordlist (like the one
Project 05 generates).

> ⚠️ Only crack hashes you own, that were given to you for a CTF/lab, or
> that you're explicitly authorized to test (e.g. during an authorized
> engagement where you dumped them yourself).

## What it does

```
$ python3 hash_cracker.py identify 5f4dcc3b5aa765d61d8327deb882cf99
Possible format(s) for: 5f4dcc3b5aa765d61d8327deb882cf99

  - MD5 or NTLM (hashlib: md5)

$ python3 hash_cracker.py crack 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt
[i] Auto-detected algorithm: md5
[i] Cracking with wordlist: wordlist.txt

[+] MATCH FOUND: password
```

## Concepts you need before reading the code

**A hash is not encryption.** Encryption is reversible (with the right
key); hashing is a deliberately one-way function — there's no "unhash"
operation. "Cracking" a hash doesn't mean reversing the math; it means
**guessing** candidate inputs, hashing each one, and checking for a
match. That's the entire idea behind every password cracker that has
ever existed, including hashcat and John the Ripper — they're just
*extremely* optimized, GPU-accelerated versions of the loop this script
does in plain Python.

**Why hash identification is ambiguous.** MD5 always produces a 128-bit
(32 hex character) output, and so does NTLM (Windows' password hash
format) — they're mathematically unrelated algorithms that just happen
to produce output the same length. There is **nothing in the hash string
itself** that tells you which one it is — you have to know where it came
from (a Linux `/etc/shadow` MD5 crypt entry looks different — it's
prefixed `$1$` — but a raw NTLM hash extracted from a Windows SAM/NTDS
dump is indistinguishable from raw MD5 by shape alone). This is why
`identify()` returns every possible match instead of guessing one — a
real tool that confidently claims "this is definitely NTLM" from shape
alone is lying to you.

**Salting, and why some hashes can't be cracked this simply.** If two
users both pick the password `"password123"`, and their hashes are
computed as plain `md5("password123")`, both hashes will be identical —
a huge information leak (an attacker who cracks one instantly knows the
other). **Salting** fixes this by mixing in a random value before
hashing (`md5(salt + password)`), so identical passwords produce
different hashes. This script's `crack()` function does a plain, unsalted
comparison — it works for the "MD5/SHA-family raw hex" formats above, but
**not** for bcrypt or Unix crypt formats (`$1$`, `$5$`, `$6$`), which
carry their salt *inside* the hash string and require a purpose-built
library that knows how to parse and reapply it. That's why those formats
are flagged "needs a dedicated library" instead of offered for cracking
here — the code is honest about its own limits rather than silently
producing wrong answers.

## Code walkthrough

Open [`hash_cracker.py`](hash_cracker.py) alongside this section.

- **`HASH_SIGNATURES`** — an ordered list of `(regex, name, hashlib_name)`
  tuples. Prefixed formats (`$2b$`, `$1$`, etc.) are checked first since
  they're unambiguous; generic hex-length patterns come after.
- **`identify()`** — runs every regex against the input and collects
  *every* match, on purpose (see "why identification is ambiguous"
  above).
- **`crack()`** — the actual attack: open the wordlist, hash each line
  with `getattr(hashlib, algo)`, compare hex digests. `getattr()` here
  turns a *string* like `"md5"` into the actual `hashlib.md5` function —
  a small but genuinely useful pattern for turning user-supplied text
  into a function call without a giant if/elif chain.
- **`main()`** — uses `argparse` subparsers (`identify` / `crack`) so
  this one script cleanly supports two different commands with their own
  arguments, instead of overloading one flag-heavy interface.

## Try it yourself (exercises)

1. Compute a few hashes yourself: in a Python shell,
   `hashlib.sha256(b"test").hexdigest()`. Run `identify` on the result —
   does it correctly report SHA-256?
2. Feed `crack` a wordlist that does **not** contain the right password
   (like the generic list without your seed word) and confirm it reports
   "No match found" instead of crashing or false-positiving.
3. Time how long cracking takes against a wordlist of 10,000 lines vs.
   100,000. This is single-threaded, unoptimized Python — explain in one
   sentence why a real cracking tool would want C/GPU code instead, and
   what stays exactly the same conceptually (the guess-hash-compare loop)
   even when the implementation gets 1000x faster.
4. (Preview of Project 46-47) This script is a plain dictionary attack
   against an *offline* hash. Sketch how a **password spraying** attack
   against a *live login form* is different — what has to change about
   the approach when you can't hash-and-compare locally, and only get a
   few attempts before a lockout?

## Running it

```bash
git clone <your-repo-url>
cd 06-hash-identifier-cracker
python3 hash_cracker.py identify 5f4dcc3b5aa765d61d8327deb882cf99
python3 hash_cracker.py crack 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt
```

Standard library only — no `pip install` needed. Pair it with
[Project 05's wordlist generator](../05-wordlist-generator) to build the
`wordlist.txt` input.

## What's next

**Project 07 — Bash Recon Automation Wrapper:** stepping into real Bash
scripting on Kali — chaining `whois`, `dig`, and `nmap` into one
automated recon script instead of running each by hand.
