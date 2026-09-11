#!/usr/bin/env python3
"""
Hash Identifier & Dictionary Cracker
=======================================
Two tools in one: guess a hash's algorithm from its shape (length and
format), and - for the algorithms Python's hashlib supports directly -
attempt to crack it by hashing every word in a wordlist and comparing.

Project 06 of a pentest/red-team learning portfolio.
Read README.md first for the concept walkthrough.

Usage:
    python3 hash_cracker.py identify <hash>
    python3 hash_cracker.py crack <hash> <wordlist_file> [--algo ALGO]

Examples:
    python3 hash_cracker.py identify 5f4dcc3b5aa765d61d8327deb882cf99
    python3 hash_cracker.py crack 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt --algo md5
"""

import argparse
import hashlib
import re

# (regex, algorithm name, hashlib name or None if hashlib can't compute it)
# Order matters: more specific prefixed formats are checked before the
# generic "N hex characters" patterns, since a bcrypt/crypt string would
# never accidentally match a plain hex-length pattern anyway, but being
# explicit about ordering makes the intent clear.
HASH_SIGNATURES = [
    (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt", None),
    (r"^\$1\$", "MD5 crypt (Unix)", None),
    (r"^\$5\$", "SHA-256 crypt (Unix)", None),
    (r"^\$6\$", "SHA-512 crypt (Unix)", None),
    (r"^[a-fA-F0-9]{32}$", "MD5 or NTLM", "md5"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1", "sha1"),
    (r"^[a-fA-F0-9]{56}$", "SHA-224", "sha224"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256", "sha256"),
    (r"^[a-fA-F0-9]{96}$", "SHA-384", "sha384"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512", "sha512"),
]


def identify(hash_string: str) -> list[tuple[str, str | None]]:
    """
    Return every (algorithm_name, hashlib_name) signature whose shape
    matches the given hash. Deliberately returns *all* matches, not just
    the first - hash identification from shape alone is inherently
    ambiguous (MD5 and NTLM are both exactly 32 hex characters, with
    nothing in the string itself to tell them apart; you have to know
    the *context* - e.g. "this came from a Windows SAM dump" - to be sure).
    """
    matches = []
    for pattern, name, algo in HASH_SIGNATURES:
        if re.match(pattern, hash_string):
            matches.append((name, algo))
    return matches


def crack(target_hash: str, wordlist_path: str, algo: str) -> str | None:
    """
    Try every line of wordlist_path as a candidate password, hash it with
    the given algorithm, and compare against target_hash. Returns the
    matching candidate, or None if nothing in the list matched.

    This is intentionally a plain, unsalted dictionary attack. Real-world
    password storage is almost always *salted* (a random value mixed in
    before hashing, so two identical passwords never produce identical
    hashes) - this simple "hash the candidate, compare" approach can't
    crack a salted hash without also knowing the salt. That's exactly why
    the bcrypt/crypt-format hashes above are flagged "needs a dedicated
    library" above instead of being crackable here: those formats carry
    their salt *inside* the hash string, and reproducing them needs a
    purpose-built library (like `bcrypt` or `passlib`) that knows the
    exact algorithm and work-factor rules.
    """
    target_hash = target_hash.lower()
    hasher_factory = getattr(hashlib, algo)

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\n\r")
            if not candidate:
                continue
            digest = hasher_factory(candidate.encode()).hexdigest()
            if digest == target_hash:
                return candidate
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Identify or dictionary-crack a hash.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    id_parser = subparsers.add_parser("identify", help="Guess the hash algorithm from its shape")
    id_parser.add_argument("hash", help="The hash string to identify")

    crack_parser = subparsers.add_parser("crack", help="Dictionary-attack a hash")
    crack_parser.add_argument("hash", help="The target hash")
    crack_parser.add_argument("wordlist", help="Path to a wordlist file, one candidate per line")
    crack_parser.add_argument(
        "--algo", default=None,
        help="hashlib algorithm name (md5, sha1, sha256, ...). "
             "If omitted, uses the first identified hashlib-crackable match.",
    )

    args = parser.parse_args()

    if args.command == "identify":
        matches = identify(args.hash)
        if not matches:
            print("[-] No known hash format matched this string's shape.")
            return
        print(f"Possible format(s) for: {args.hash}\n")
        for name, algo in matches:
            note = f" (hashlib: {algo})" if algo else " (needs a dedicated library to crack)"
            print(f"  - {name}{note}")

    elif args.command == "crack":
        algo = args.algo
        if algo is None:
            hashlib_matches = [m for m in identify(args.hash) if m[1]]
            if not hashlib_matches:
                parser.error(
                    "Could not auto-identify a hashlib-crackable algorithm - "
                    "pass --algo explicitly (e.g. --algo sha256)"
                )
            algo = hashlib_matches[0][1]
            print(f"[i] Auto-detected algorithm: {algo}")

        if not hasattr(hashlib, algo):
            parser.error(f"'{algo}' is not a hashlib algorithm on this system")

        print(f"[i] Cracking with wordlist: {args.wordlist}")
        result = crack(args.hash, args.wordlist, algo)
        if result is not None:
            print(f"\n[+] MATCH FOUND: {result}")
        else:
            print("\n[-] No match found in wordlist.")


if __name__ == "__main__":
    main()
