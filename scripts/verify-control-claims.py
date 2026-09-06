#!/usr/bin/env python3
"""Verify that every test cited by the threat model actually exists.

AppSec Framework's thesis is that security tools overstate what they verified. The threat
model marks controls TESTED and names the test that proves each one. If a cited
test is renamed or deleted, that claim silently becomes false — which is exactly
the failure this project exists to prevent, committed against ourselves.

Exits non-zero if any cited test is missing.
"""
import re
import subprocess
import sys
from pathlib import Path

THREAT_MODEL = Path("docs/security/threat-model.md")


def main() -> int:
    if not THREAT_MODEL.exists():
        print(f"error: {THREAT_MODEL} not found", file=sys.stderr)
        return 1

    doc = THREAT_MODEL.read_text()
    cited = {m.group(2) for m in re.finditer(r"`(?:([a-z]+)\.)?(Test[A-Za-z0-9_]+)`", doc)}

    found = subprocess.run(
        ["grep", "-rhoE", r"^func (Test[A-Za-z0-9_]+)", "--include=*_test.go", "."],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    actual = {line.split()[1] for line in found.strip().splitlines() if line.strip()}

    missing = sorted(cited - actual)
    if missing:
        print("error: the threat model cites tests that do not exist:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print(
            "\nEither restore the test or downgrade the control's status from TESTED.",
            file=sys.stderr,
        )
        return 1

    print(f"ok: all {len(cited)} tests cited by the threat model exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
