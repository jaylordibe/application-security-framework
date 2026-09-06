#!/usr/bin/env python3
"""Fail if user-facing text asserts that a target is secure.

AppSec Framework must never claim an application is secure; it can only report what it
tested and what it did not. This guards against that claim creeping into the
code or the README.

Negated forms are allowed and in fact required — "AppSec Framework does not prove
that an application is secure" is the message we want.
"""
import re
import subprocess
import sys

# The assertion we forbid.
CLAIM = re.compile(r"\b(is|are|was|were)\s+secure\b|\b(proven|guaranteed|verified)\s+secure\b", re.I)

# Negations that make the sentence a disclaimer rather than a claim. Checked
# against the text preceding the match on the same line.
NEGATION = re.compile(
    r"\b(not|never|cannot|can't|doesn't|does not|don't|do not|no|without|"
    r"neither|nor|rather than|instead of)\b",
    re.I,
)

PATHS = ["--include=*.go", "--include=*.md", "--include=*.yaml", "--include=*.json"]


def main() -> int:
    out = subprocess.run(
        ["grep", "-rIn", "--exclude-dir=.git", *PATHS, "-E", r"(is|are|was|were|proven|guaranteed|verified) secure", "."],
        capture_output=True,
        text=True,
        check=False,
    ).stdout

    offenders = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        path, lineno, text = parts
        m = CLAIM.search(text)
        if not m:
            continue
        # Allow the claim when it is negated earlier in the same sentence.
        preceding = text[: m.start()]
        if NEGATION.search(preceding):
            continue
        offenders.append(f"{path}:{lineno}: {text.strip()}")

    if offenders:
        print("error: user-facing text asserts that a target is secure:", file=sys.stderr)
        for o in offenders:
            print(f"  {o}", file=sys.stderr)
        print(
            "\nAppSec Framework reports what it tested and what it did not. It never "
            "concludes "
            "that an application is secure.",
            file=sys.stderr,
        )
        return 1

    print("ok: no text asserts that a target is secure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
