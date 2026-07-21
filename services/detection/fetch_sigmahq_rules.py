#!/usr/bin/env python3
"""
Vendors the SigmaHQ ruleset subset THOS actually evaluates into
services/detection/sigma_rules_hq/, per the scope documented in
services/detection/sigma_rules_hq/VERSION.txt.

THOS targets on-prem / air-gapped deployments (see README.md
"Security"). sigmahq_engine.py only reads rules from disk; it never
contacts GitHub. This script is used both for the preferred offline
vendoring workflow and by Compose's one-shot sigmahq-rules-init service
when no vendored or previously downloaded corpus is available.

What it does:
  1. Sparse-checkouts SigmaHQ/sigma at --ref (default: master) --
     `--filter=blob:none --no-checkout` + cone-mode sparse-checkout
     limited to the seven rules/ subtrees below, so it doesn't pull
     the whole repository (rules/cloud, rules-emerging-threats/, the
     web app under `web/`, docs, tests, etc. are 300+ MB combined).
  2. Copies every .yml/.yaml file in those subtrees into
     sigma_rules_hq/, preserving the upstream directory layout, EXCEPT
     Sigma correlation rules (files with a top-level `correlation:`
     key) -- pySigma parses those as SigmaCorrelationRule, a distinct
     type from SigmaRule that needs a time-windowed join engine THOS's
     evaluate-each-record-independently model doesn't have. See
     sigmahq_engine.py's module docstring.
  3. Rewrites VERSION.txt with the new commit hash, fetch date, and
     rule count so the vendored copy is traceable to an exact upstream
     revision (never a moving "master" pointer).

Usage:
    python3 services/detection/fetch_sigmahq_rules.py
    python3 services/detection/fetch_sigmahq_rules.py --ref <commit-or-branch>
    python3 services/detection/fetch_sigmahq_rules.py --ref <commit> --dest /rules

Requires `git` >= 2.25 (cone-mode sparse-checkout) on PATH.
"""
from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
import tempfile

REPO_URL = "https://github.com/SigmaHQ/sigma.git"
DEFAULT_REF = "master"

# rules/{...} subtrees vendored. See VERSION.txt for the full rationale
# on why rules/cloud, rules/macos, deprecated/, unsupported/,
# rules-placeholder/, rules-emerging-threats/, rules-threat-hunting/,
# rules-dfir/, and rules-compliance/ are deliberately excluded.
INCLUDED_SUBTREES = [
    "rules/windows",
    "rules/linux",
    "rules/network",
    "rules/application",
    "rules/web",
    "rules/category",
    "rules/identity",
]

DEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_rules_hq")

VERSION_TEMPLATE = """\
SigmaHQ/sigma vendored ruleset
===============================

Source:  https://github.com/SigmaHQ/sigma
Commit:  {commit} (ref: {ref})
Fetched: {fetched}

Scope: the rules/{{windows,linux,network,application,web,category,identity}}
subtrees only ({count} rules) -- i.e. every logsource this platform's
normalized log record schema (services/siem/*) can plausibly carry text
for. Excluded on purpose:

  - rules/cloud (~230 rules)  -- AWS/GCP/Azure/M365 control-plane JSON
    events with provider-specific field names (eventSource, eventName,
    requestParameters.*, etc.) that THOS's flat {{host,user,event,detail}}
    schema and file_log_parser.py's ingestion formats (EVTX/CEF/syslog/
    CSV/JSON/pcap) have no realistic path to populating correctly. Vendoring
    them would inflate the "rules evaluated" count without adding real
    detection capability, which is the same complaint this replaces.
  - rules/macos (~69 rules) -- out of scope for this platform today.
  - deprecated/, unsupported/, rules-placeholder/, rules-emerging-threats/,
    rules-threat-hunting/, rules-dfir/, rules-compliance/ -- not part of
    the stable, maintained detection ruleset proper.
  - Sigma correlation rules (aggregation/count() rules) -- pySigma parses
    these as a distinct SigmaCorrelationRule type; THOS evaluates each log
    record independently (no time-windowed join), so they're not loadable
    by design here, same limitation the original hand-rolled engine
    documented. {correlation_count} were excluded from this fetch on that basis.

The application runtime never contacts GitHub. Compose's one-shot
sigmahq-rules-init may download this pinned commit into a persistent volume
when the reviewed YAML files are absent. For a deliberately air-gapped
deployment, vendor the corpus before deployment by running:

    python3 services/detection/fetch_sigmahq_rules.py --ref <commit>

...from a machine with network + git access, then review and commit the
resulting diff under services/detection/sigma_rules_hq/.
"""


def _run(cmd: list[str], **kw) -> None:
    subprocess.run(cmd, check=True, **kw)


def _sparse_clone(ref: str, workdir: str) -> tuple[str, str]:
    clone_dir = os.path.join(workdir, "sigma")
    _run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", REPO_URL, clone_dir])
    _run(["git", "sparse-checkout", "init", "--cone"], cwd=clone_dir)
    _run(["git", "sparse-checkout", "set", *INCLUDED_SUBTREES], cwd=clone_dir)
    _run(["git", "checkout", "--quiet", ref], cwd=clone_dir)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=clone_dir
    ).decode().strip()
    return clone_dir, commit


def _is_correlation_rule(path: str) -> bool:
    """A Sigma YAML file is a correlation rule if it has a top-level
    `correlation:` key rather than `detection:`. Checked on raw text
    (not a full YAML parse) so one malformed file can't abort vendoring."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.rstrip("\n")
                if stripped.startswith("correlation:"):
                    return True
                if stripped.startswith("detection:"):
                    return False
    except OSError:
        return False
    return False


def _clear_directory(path: str) -> None:
    """Clear a directory without removing its root (which may be a volume)."""
    resolved = os.path.abspath(path)
    if os.path.dirname(resolved) == resolved:
        raise ValueError(f"refusing to clear filesystem root: {resolved}")
    os.makedirs(path, exist_ok=True)
    for name in os.listdir(path):
        child = os.path.join(path, name)
        if os.path.isdir(child) and not os.path.islink(child):
            shutil.rmtree(child)
        else:
            os.unlink(child)


def _vendor(clone_dir: str, dest_dir: str = DEST_DIR) -> tuple[int, int]:
    _clear_directory(dest_dir)

    vendored = 0
    skipped_correlation = 0
    for subtree in INCLUDED_SUBTREES:
        src_root = os.path.join(clone_dir, subtree)
        if not os.path.isdir(src_root):
            continue
        for root, _dirs, files in os.walk(src_root):
            for name in files:
                if not name.endswith((".yml", ".yaml")):
                    continue
                src_path = os.path.join(root, name)
                if _is_correlation_rule(src_path):
                    skipped_correlation += 1
                    continue
                rel = os.path.relpath(src_path, clone_dir)
                dst_path = os.path.join(dest_dir, rel)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                vendored += 1
    return vendored, skipped_correlation


def _write_version_file(
    commit: str,
    ref: str,
    count: int,
    correlation_count: int,
    dest_dir: str = DEST_DIR,
) -> None:
    content = VERSION_TEMPLATE.format(
        commit=commit,
        ref=ref,
        fetched=datetime.date.today().isoformat(),
        count=count,
        correlation_count=correlation_count,
    )
    with open(os.path.join(dest_dir, "VERSION.txt"), "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", default=DEFAULT_REF,
                         help="Branch, tag, or commit to vendor (default: master)")
    parser.add_argument(
        "--dest",
        default=DEST_DIR,
        help=f"Destination directory (default: {DEST_DIR})",
    )
    args = parser.parse_args()

    destination = os.path.abspath(args.dest)
    if os.path.dirname(destination) == destination:
        parser.error("--dest must not be a filesystem root")
    args.dest = destination

    if shutil.which("git") is None:
        print("error: git is required on PATH to fetch the SigmaHQ ruleset.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="sigmahq-fetch-") as workdir:
        try:
            clone_dir, commit = _sparse_clone(args.ref, workdir)
        except subprocess.CalledProcessError as e:
            print(f"error: git operation failed ({e}). Do you have network access?", file=sys.stderr)
            return 1
        vendored, skipped_correlation = _vendor(clone_dir, args.dest)

    _write_version_file(commit, args.ref, vendored, skipped_correlation, args.dest)

    print(f"Vendored {vendored} SigmaHQ rules (skipped {skipped_correlation} correlation "
          f"rules) at commit {commit} into {args.dest}")
    if os.path.abspath(args.dest) == os.path.abspath(DEST_DIR):
        print("Review the diff, then commit services/detection/sigma_rules_hq/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
