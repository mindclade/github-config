#!/usr/bin/env python3
"""Synchronise reviewed authority revisions with their sibling repository mains.

config/actions-policy.yaml records, for every reviewed authority repository, the
exact revision that was reviewed. The catalog contract requires that revision to
equal the sibling repository's current main, so the attestation cannot silently
describe a revision that main has already moved past.

That invariant is deliberate, but it makes every commit to a reviewed sibling
(.github, bootstrap, infrastructure-live) fail this repository's contract suite
until the policy is re-attested. Hand-editing SHAs across repositories is
error-prone and easy to get half-right, so this tool performs the update.

    python3 tools/sync_authority_revisions.py --check   # report drift, exit 1
    python3 tools/sync_authority_revisions.py           # rewrite the policy

Only the `revision` field of reviewed authorities is touched. The
`implementation_revision` pin that consumers resolve is deliberately allowed to
lag and is never rewritten here - advancing it also requires advancing the
consumer workflow pins, which is a separate reviewed change.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

POLICY = Path("config") / "actions-policy.yaml"

# Matches an authority block's repository name followed by its revision line,
# capturing the surrounding text so only the SHA is rewritten.
AUTHORITY = re.compile(
    r"(- repository: (?P<name>[^\n]+)\n(?P<indent>\s+)revision: )(?P<revision>[0-9a-f]{40})"
)


def sibling_main(repository: str, estate_root: Path) -> str | None:
    """Return the sibling repository's main HEAD, or None if unavailable."""
    path = estate_root / repository
    if not (path / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "refs/heads/main"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without rewriting the policy; exit 1 when drift exists",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="github-config checkout root (default: current directory)",
    )
    arguments = parser.parse_args()

    policy_path = arguments.root / POLICY
    if not policy_path.exists():
        print(f"{policy_path} not found", file=sys.stderr)
        return 2

    estate_root = arguments.root.resolve().parent
    original = policy_path.read_text(encoding="utf-8")
    drift: list[tuple[str, str, str]] = []
    skipped: list[str] = []

    def replace(match: re.Match[str]) -> str:
        repository = match.group("name").strip()
        current = match.group("revision")
        head = sibling_main(repository, estate_root)
        if head is None:
            skipped.append(repository)
            return match.group(0)
        if head != current:
            drift.append((repository, current, head))
            return match.group(1) + head
        return match.group(0)

    updated = AUTHORITY.sub(replace, original)

    for repository in skipped:
        print(f"skipped {repository}: sibling checkout not present", file=sys.stderr)

    if not drift:
        print("authority revisions are in sync")
        return 0

    for repository, was, now in drift:
        print(f"{repository}: {was[:12]} -> {now[:12]}")

    if arguments.check:
        print(
            "\nauthority revisions are stale; run `just sync-authority-revisions` "
            "and commit the result",
            file=sys.stderr,
        )
        return 1

    policy_path.write_text(updated, encoding="utf-8")
    print(f"\nupdated {policy_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
