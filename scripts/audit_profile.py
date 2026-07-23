#!/usr/bin/env python3
"""Fail when a profile recommendation is broken, misleading, or unsafe."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "XJM-free-profile-audit/1.0"
GITHUB_REPOS = (
    "apple-presubmit-audit",
    "claude-agent-ledger",
    "iOS-apps-portfolio",
)
SURFACES = (
    ("https://tinyweblab.com", "Tiny Web Lab"),
    ("https://jiexiang.dev", "<title>Jie Xiang"),
    ("https://jiexiang.dev/blog", "Writing"),
    ("https://bsky.app/profile/jiexiang.dev", "@jiexiang.dev on Bluesky"),
)


class Audit:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"FAIL: {message}", file=sys.stderr)

    def pass_(self, message: str) -> None:
        print(f"PASS: {message}")


def request_bytes(url: str) -> bytes:
    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--retry",
            "3",
            "--retry-all-errors",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--user-agent",
            USER_AGENT,
            url,
        ],
        capture_output=True,
        check=False,
        timeout=130,
    )
    if result.returncode != 0:
        raise RuntimeError("request failed")
    return result.stdout


def request_text(url: str) -> str:
    return request_bytes(url).decode("utf-8", errors="replace")


def request_json(url: str) -> object:
    return json.loads(request_bytes(url))


def audit_surfaces(audit: Audit) -> None:
    for url, marker in SURFACES:
        try:
            body = request_text(url)
        except (RuntimeError, ValueError) as error:
            audit.fail(f"{url} could not be verified ({type(error).__name__})")
            continue
        if marker not in body:
            audit.fail(f"{url} is reachable but its identity marker is missing")
            continue
        audit.pass_(f"{url} is reachable and identifies the intended surface")

    oembed_url = "https://publish.twitter.com/oembed?" + urllib.parse.urlencode(
        {"url": "https://x.com/FreJieMei"}
    )
    try:
        payload = request_json(oembed_url)
    except (RuntimeError, ValueError) as error:
        audit.fail(f"X profile could not be verified ({type(error).__name__})")
    else:
        if not isinstance(payload, dict) or payload.get("url") != (
            "https://x.com/FreJieMei"
        ):
            audit.fail("X oEmbed resolved to an unexpected profile")
        else:
            audit.pass_("X profile resolves through X's public oEmbed endpoint")


def audit_github_repositories(audit: Audit) -> None:
    try:
        payload = request_json(
            "https://api.github.com/users/XJM-free/repos?"
            + urllib.parse.urlencode(
                {"per_page": 100, "type": "owner", "sort": "updated"}
            )
        )
    except (RuntimeError, ValueError) as error:
        audit.fail(
            "GitHub repository metadata could not be verified "
            f"({type(error).__name__})"
        )
        return

    if not isinstance(payload, list):
        audit.fail("GitHub returned unexpected repository metadata")
        return
    repositories = {
        repo.get("name"): repo for repo in payload if isinstance(repo, dict)
    }

    for name in GITHUB_REPOS:
        repo = repositories.get(name)
        if repo is None:
            audit.fail(f"{name} is missing from the public repository list")
            continue

        problems = []
        if repo.get("private") is not False:
            problems.append("not public")
        if repo.get("fork") is not False:
            problems.append("is a fork")
        if repo.get("archived") is not False:
            problems.append("is archived")
        if not repo.get("description"):
            problems.append("has no description")
        if repo.get("default_branch") != "main":
            problems.append("does not use main as its default branch")

        if problems:
            audit.fail(f"{name}: " + "; ".join(problems))
        else:
            audit.pass_(f"{name} is public, original, active, and described")

    raw_portfolio = (
        "https://raw.githubusercontent.com/"
        "XJM-free/iOS-apps-portfolio/main/README.md"
    )
    try:
        portfolio = request_text(raw_portfolio)
    except RuntimeError as error:
        audit.fail(f"portfolio evidence could not be read ({type(error).__name__})")
    else:
        required = (
            "53 iOS apps shipped solo",
            "Public verification",
            "currently unavailable",
        )
        missing = [marker for marker in required if marker not in portfolio]
        if missing:
            audit.fail("portfolio evidence is missing reviewed availability claims")
        else:
            audit.pass_("portfolio distinguishes shipped work from public availability")


def audit_package(audit: Audit) -> None:
    try:
        package = request_json(
            "https://registry.npmjs.org/claude-agent-ledger/latest"
        )
    except (RuntimeError, ValueError) as error:
        audit.fail(f"npm package could not be verified ({type(error).__name__})")
        return

    if (
        not isinstance(package, dict)
        or package.get("name") != "claude-agent-ledger"
        or not package.get("version")
    ):
        audit.fail("npm returned unexpected claude-agent-ledger metadata")
    else:
        audit.pass_(
            "claude-agent-ledger is installable from npm "
            f"(version {package['version']})"
        )


def tracked_paths() -> list[str]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
    )
    return [
        item.decode("utf-8", errors="replace")
        for item in output.split(b"\0")
        if item
    ]


def unsafe_path(path: str) -> bool:
    lowered = path.lower()
    name = Path(lowered).name
    if lowered.startswith(".wrangler/") or "/.wrangler/" in lowered:
        return True
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if name in {"id_rsa", "id_ed25519", "credentials", "secrets"}:
        return True
    return Path(lowered).suffix in {".pem", ".key", ".p12", ".pfx"}


def audit_sensitive_material(audit: Audit) -> None:
    bad_paths = sorted(path for path in tracked_paths() if unsafe_path(path))
    if bad_paths:
        for path in bad_paths:
            audit.fail(f"tracked sensitive/generated path: {path}")
    else:
        audit.pass_("no sensitive or local deployment paths are tracked")

    token_patterns = (
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "github" + "_pat_[A-Za-z0-9_]{20,}",
        "gh" + "[pousr]_[A-Za-z0-9]{30,}",
        "AK" + "IA[0-9A-Z]{16}",
        "sk" + "-[A-Za-z0-9_-]{20,}",
        "CLOUDFLARE_" + "API_TOKEN[[:space:]]*[:=]"
        "[[:space:]]*['\"]?[A-Za-z0-9_-]{20,}",
    )
    revisions = subprocess.check_output(
        ["git", "rev-list", "--all"],
        cwd=ROOT,
        text=True,
    ).split()
    if not revisions:
        audit.pass_("repository history is empty")
        return

    scan = subprocess.run(
        [
            "git",
            "grep",
            "-I",
            "-l",
            "-E",
            "-e",
            "|".join(token_patterns),
            *revisions,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if scan.returncode not in (0, 1):
        audit.fail("repository history scan could not complete")
        return

    matched_paths = sorted(
        {
            line.split(":", 1)[1]
            for line in scan.stdout.splitlines()
            if ":" in line
        }
    )
    if matched_paths:
        for path in matched_paths:
            audit.fail(f"possible credential pattern in repository history: {path}")
    else:
        audit.pass_("repository history contains no recognized credential patterns")


def main() -> int:
    audit = Audit()
    audit_sensitive_material(audit)
    audit_surfaces(audit)
    audit_github_repositories(audit)
    audit_package(audit)

    if audit.failures:
        print(
            f"\nProfile audit failed with {len(audit.failures)} problem(s).",
            file=sys.stderr,
        )
        return 1
    print("\nProfile audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
