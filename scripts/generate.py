#!/usr/bin/env python3
"""Download EasyList-family rules and convert them to domain rule files.

For every source in SOURCES, two files are written to <repo>/rules/:
  <name>.json  - sing-box rule-set source (version 5, domain_suffix)
  <name>.list  - one "DOMAIN-SUFFIX,<domain>" per line

Usage:
  python scripts/generate.py                        # all sources, downloaded
  python scripts/generate.py easy                   # only the named source(s)
  python scripts/generate.py easy=./local.txt       # use a local file (testing)

To add another EasyList-format list, just add one entry to SOURCES.

Extraction philosophy (so upstream changes don't break it):
  * Structure-based, not position-based: every line is classified on its own,
    so added/removed/reordered rules, new comments, CRLF, BOM, spaces,
    upper-case and IDN domains are all handled.
  * @@ exceptions that fully unblock a domain remove it from the output;
    partial ones (domain=, script, generichide...) are ignored.
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

# name -> (url, minimum plausible number of domains)
# The minimum is a sanity check: fewer than this means the download or the
# parsing is broken, so the existing output is left untouched.
SOURCES = {
    "easy": (
        "https://raw.githubusercontent.com/easylist/easylist/master/"
        "easylist/easylist_adservers.txt", 1000),
    "easychina": (
        "https://raw.githubusercontent.com/easylist/easylistchina/master/"
        "easylistchina.txt", 1000),
    "chinesefilter": (
        "https://adguardteam.github.io/AdguardFilters/ChineseFilter/"
        "sections/adservers.txt", 100),
}
OUT_DIR = Path(__file__).resolve().parent.parent / "rules"

# ---- sanity limits --------------------------------------------------------
# (per-source minimum lives in SOURCES)
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
          "exception" -> host is fully whitelisted by an @@ rule (removes the block)
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

    if sep and not options_are_safe(opts):
        # A block rule with narrowing options may over-block.
        # An exception with narrowing options (domain=, script, generichide...)
        # only unblocks part of the domain, so it must not remove the block.
        return "skip", ("partial @@ exception (ignored)" if is_exception
                        else "restrictive options (may over-block)")
    return ("exception" if is_exception else "block"), host


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


def previous_count(name: str) -> int:
    path = OUT_DIR / f"{name}.list"
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as f:
        return sum(1 for _ in f)


def build(name: str, text: str, min_domains: int) -> None:
    """Extract domains from `text` and write <name>.json / <name>.list.

    Raises RuntimeError (leaving existing output untouched) if the result
    looks broken.
    """
    domains, stats = extract_domains(text)

    print(f"[{name}] extracted {len(domains)} domains; skipped/dropped:")
    for reason, n in stats.most_common():
        print(f"  {n:>6}  {reason}")

    if len(domains) < min_domains:
        raise RuntimeError(f"only {len(domains)} domains extracted; refusing to overwrite rules")
    old = previous_count(name)
    if (old and len(domains) < old * MAX_SHRINK_RATIO
            and os.environ.get("ALLOW_SHRINK") != "1"):
        raise RuntimeError(f"domains dropped from {old} to {len(domains)}; upstream format "
                           f"may have changed. Check the source, or set ALLOW_SHRINK=1.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ruleset = {"version": 5, "rules": [{"domain_suffix": domains}]}
    (OUT_DIR / f"{name}.json").write_text(
        json.dumps(ruleset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (OUT_DIR / f"{name}.list").write_text(
        "".join(f"DOMAIN-SUFFIX,{d}\n" for d in domains), encoding="utf-8"
    )
    print(f"[{name}] wrote {len(domains)} domains to {OUT_DIR}")


def main() -> None:
    # args: "name" or "name=local_file"; no args => every source
    requested: dict[str, str | None] = {}
    for arg in sys.argv[1:]:
        name, _, path = arg.partition("=")
        if name not in SOURCES:
            sys.exit(f"unknown source '{name}'; choose from: {', '.join(SOURCES)}")
        requested[name] = path or None
    if not requested:
        requested = {name: None for name in SOURCES}

    failed = []
    for name, local_path in requested.items():
        try:
            if local_path:
                text = Path(local_path).read_text(encoding="utf-8-sig", errors="replace")
            else:
                text = download(SOURCES[name][0])
            build(name, text, SOURCES[name][1])
        except Exception as exc:  # noqa: BLE001 - keep going so other sources still update
            print(f"[{name}] FAILED: {exc}", file=sys.stderr)
            failed.append(name)
    if failed:
        sys.exit(f"failed sources: {', '.join(failed)}")


if __name__ == "__main__":
    main()
