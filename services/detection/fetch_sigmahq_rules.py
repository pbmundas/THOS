#!/usr/bin/env python3
"""
Vendors the SigmaHQ ruleset subset THOS actually evaluates into
services/detection/sigma_rules_hq/, per the scope documented in
services/detection/sigma_rules_hq/VERSION.txt.

THOS targets on-prem / air-gapped deployments (see README.md
"Security"), so the running platform never fetches rules from GitHub
at runtime -- sigmahq_engine.py only ever reads the vendored copy on
disk. This script is the *offline vendoring step*: run it once from a
machine with network + git access (NOT inside the THOS container),
review the diff, and commit the result under sigma_rules_hq/. It is
not imported by any service at runtime.

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

This is a deliberately air-gapped vendoring (THOS targets on-prem/
air-gapped deployments -- see README.md "Security") rather than a
runtime fetch from GitHub. To refresh it against upstream, run:

    python3 services/detection/fetch_sigmahq_rules.py

...from a machine with network + git access (not inside the container),
then commit the resulting diff under services/detection/sigma_rules_hq/.
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


def _vendor(clone_dir: str) -> tuple[int, int]:
    if os.path.isdir(DEST_DIR):
        shutil.rmtree(DEST_DIR)
    os.makedirs(DEST_DIR)

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
                dst_path = os.path.join(DEST_DIR, rel)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                vendored += 1
    return vendored, skipped_correlation


def _write_version_file(commit: str, ref: str, count: int, correlation_count: int) -> None:
    content = VERSION_TEMPLATE.format(
        commit=commit,
        ref=ref,
        fetched=datetime.date.today().isoformat(),
        count=count,
        correlation_count=correlation_count,
    )
    with open(os.path.join(DEST_DIR, "VERSION.txt"), "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", default=DEFAULT_REF,
                         help="Branch, tag, or commit to vendor (default: master)")
    args = parser.parse_args()

    if shutil.which("git") is None:
        print("error: git is required on PATH to fetch the SigmaHQ ruleset.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="sigmahq-fetch-") as workdir:
        try:
            clone_dir, commit = _sparse_clone(args.ref, workdir)
        except subprocess.CalledProcessError as e:
            print(f"error: git operation failed ({e}). Do you have network access?", file=sys.stderr)
            return 1
        vendored, skipped_correlation = _vendor(clone_dir)

    _write_version_file(commit, args.ref, vendored, skipped_correlation)

    print(f"Vendored {vendored} SigmaHQ rules (skipped {skipped_correlation} correlation "
          f"rules) at commit {commit} into {DEST_DIR}")
    print("Review the diff, then commit services/detection/sigma_rules_hq/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
