#!/usr/bin/env python3
"""Download EasyList ad-server rules and convert them to domain rule files.

Outputs (written to <repo>/rules/):
  easy.json  - sing-box rule-set source (version 5, domain_suffix)
  easy.list  - one "DOMAIN-SUFFIX,<domain>" per line

Usage:
  python scripts/generate.py                 # download from SOURCE_URL
  python scripts/generate.py path/to/file    # use a local copy (for testing)

Extraction philosophy (so upstream changes don't break it):
  * Structure-based, not position-based: every line is classified on its own,
    so added/removed/reordered rules, new comments, CRLF, BOM, spaces,
    upper-case and IDN domains are all handled.
  * Fail-safe: only rules that clearly mean "block this whole domain" are kept.
    Anything unrecognised (unknown options, paths, wildcards, ports, regex...)
    is skipped rather than guessed.
  * Sanity checks: refuse to overwrite the output if the result looks broken.
"""
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/easylist/easylist/master/"
    "easylist/easylist_adservers.txt"
)
OUT_DIR = Path(__file__).resolve().parent.parent / "rules"

# ---- sanity limits --------------------------------------------------------
MIN_EXPECTED_DOMAINS = 1000   # fewer than this => download/parse is broken
MAX_SHRINK_RATIO = 0.5        # new < 50% of previous output => refuse
                              # (set ALLOW_SHRINK=1 to override deliberately)

# ---- option handling ------------------------------------------------------
# Options that do not narrow the rule: the whole domain is still blocked.
NEUTRAL_OPTIONS = {"third-party", "3p", "important", "all", "document", "doc"}
# "popup" alone only blocks popups (narrow); it is fine next to document/all.
WHOLE_PAGE_OPTIONS = {"all", "document", "doc"}
# Everything else (script, image, xmlhttprequest, subdocument, media, ...),
# any "~negation", any "key=value" (domain=, denyallow=, ...) and any option
# we have never seen is treated as restrictive => rule skipped.

# ---- host validation ------------------------------------------------------
HOST_CHARS_RE = re.compile(r"^[\w.-]+$")          # \w also covers IDN letters
LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def download(url: str, retries: int = 3) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "easylist-domain-converter"})
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            if attempt == retries:
                raise
            print(f"download failed ({exc}), retry {attempt}/{retries}", file=sys.stderr)
            time.sleep(5 * attempt)
    raise RuntimeError("unreachable")


def normalize_host(raw: str) -> str | None:
    """Return a clean lower-case ASCII domain, or None if it is not one."""
    host = raw
    while host.startswith("*."):          # ||*.example.com^  ==  ||example.com^
        host = host[2:]
    if not host or not HOST_CHARS_RE.match(host):
        return None
    try:                                  # IDN -> punycode (no-op for ASCII)
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    host = host.lower()
    if len(host) > 253:
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(x) for x in labels):
        return None                       # single label, empty label, trailing dot...
    try:                                  # ignore IP address rules
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if labels[-1].isdigit():              # partial / odd IP like 1.2.3
        return None
    return host


def options_are_safe(opts: str) -> bool:
    """True only if the options do not narrow the block to part of the domain."""
    names = [o.strip().lower() for o in opts.split(",") if o.strip()]
    for name in names:
        if name in NEUTRAL_OPTIONS:
            continue
        if name == "popup" and any(n in WHOLE_PAGE_OPTIONS for n in names):
            continue
        return False
    return True


def classify(line: str) -> tuple[str, str | None]:
    """Return (kind, host_or_reason).

    kind: "block"     -> host should be blocked
          "exception" -> host appears in an @@ rule (used to drop it, fail-safe)
          "skip"      -> ignored; second item is the reason
    """
    line = line.strip().lstrip("\ufeff")
    if not line or line[0] in "![#":
        return "skip", "comment/blank"

    is_exception = line.startswith("@@")
    if is_exception:
        line = line[2:]
    if not line.startswith("||"):
        return "skip", "not a ||domain rule"   # IP `|1.2.3.4`, regex, cosmetic...

    body = line[2:]
    pattern, sep, opts = body.partition("$")
    pattern = pattern.rstrip("|")
    if pattern.endswith("^"):
        pattern = pattern[:-1]

    host = normalize_host(pattern)
    if host is None:
        if re.fullmatch(r"[\d.]+", pattern):
            return "skip", "ip address"
        return "skip", "path/wildcard/port/partial domain"

    if is_exception:
        return "exception", host
    if sep and not options_are_safe(opts):
        return "skip", "restrictive options (may over-block)"
    return "block", host


def extract_domains(text: str) -> tuple[list[str], Counter]:
    blocked: set[str] = set()
    excepted: set[str] = set()
    stats: Counter = Counter()
    for line in text.splitlines():
        kind, value = classify(line)
        if kind == "block":
            blocked.add(value)
        elif kind == "exception":
            excepted.add(value)
        else:
            stats[value] += 1
    dropped = blocked & excepted
    stats["dropped: has @@ exception"] = len(dropped)
    return sorted(blocked - excepted), stats


def previous_count() -> int:
    path = OUT_DIR / "easy.list"
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as f:
        return sum(1 for _ in f)


def main() -> None:
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8-sig", errors="replace")
    else:
        text = download(SOURCE_URL)

    domains, stats = extract_domains(text)

    print(f"extracted {len(domains)} domains; skipped/dropped:")
    for reason, n in stats.most_common():
        print(f"  {n:>6}  {reason}")

    if len(domains) < MIN_EXPECTED_DOMAINS:
        sys.exit(f"only {len(domains)} domains extracted; refusing to overwrite rules")
    old = previous_count()
    if (old and len(domains) < old * MAX_SHRINK_RATIO
            and os.environ.get("ALLOW_SHRINK") != "1"):
        sys.exit(f"domains dropped from {old} to {len(domains)}; upstream format "
                 f"may have changed. Check the source, or set ALLOW_SHRINK=1.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ruleset = {"version": 5, "rules": [{"domain_suffix": domains}]}
    (OUT_DIR / "easy.json").write_text(
        json.dumps(ruleset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (OUT_DIR / "easy.list").write_text(
        "".join(f"DOMAIN-SUFFIX,{d}\n" for d in domains), encoding="utf-8"
    )
    print(f"wrote {len(domains)} domains to {OUT_DIR}")


if __name__ == "__main__":
    main()
