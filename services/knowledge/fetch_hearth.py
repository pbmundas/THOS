#!/usr/bin/env python3
"""
Fetch + convert the real HEARTH threat-hunting-hypothesis repository
(https://github.com/THORCollective/HEARTH) into the JSON shape that
ingest_knowledge_base.py's ingest_hearth() expects.

This replaces the old 3-item (later 7-item) hardcoded/seed hypothesis list
with the full public HEARTH corpus (~270 hypotheses across the Flames/
Embers/Alchemy categories) as of whenever you run this script.

Usage (run locally, not inside a container — needs `git` + `pyyaml`):

    pip install pyyaml --break-system-packages   # or in a venv
    python3 services/knowledge/fetch_hearth.py

Then re-run ingestion so ChromaDB picks up the new file:

    docker compose run --rm kb-ingest

Re-run this script any time you want to refresh from upstream — it's
idempotent (re-clones to a temp dir, overwrites the output JSON).

Note: this script does NOT run automatically as part of `docker compose up`.
It's a one-time (or occasional refresh) data-prep step, kept separate from
the kb-ingest container so that container doesn't need git/network access
to GitHub at every startup.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit(
        "PyYAML is required. Install it first:\n"
        "    pip install pyyaml --break-system-packages"
    )

REPO_URL = "https://github.com/THORCollective/HEARTH.git"
CATEGORIES = ["Flames", "Embers", "Alchemy"]
SKIP_FILES = {"secret.md"}  # THOR Collective's ARG/puzzle easter egg, not a real hypothesis

TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(
    HERE, "..", "..", "data", "knowledge_base", "hearth", "hearth_full.json"
)


def parse_frontmatter_file(path: str, category: str) -> dict | None:
    with open(path, encoding="utf-8") as f:
        content = f.read()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not m:
        return None
    fm = yaml.safe_load(m.group(1)) or {}
    hid = str(fm.get("id") or os.path.splitext(os.path.basename(path))[0])
    title = (fm.get("hypothesis") or "").strip().replace("\n", " ")
    if not title:
        return None
    tactics = fm.get("tactics") or []
    techniques = fm.get("techniques") or []
    text = title
    notes = fm.get("notes", "")
    if notes:
        text = f"{title} {notes}".strip()
    return {
        "id": hid,
        "title": title[:140],
        "tactic": tactics[0] if tactics else "",
        "technique": techniques[0] if techniques else "",
        "text": text,
        "category": category,
        "all_tactics": tactics,
        "all_techniques": techniques,
        "tags": fm.get("tags") or [],
    }


def parse_table_file(path: str, category: str) -> dict | None:
    """Older-format files: '# H180' heading + a markdown table + prose body,
    instead of YAML frontmatter."""
    with open(path, encoding="utf-8") as f:
        content = f.read()
    hid_match = re.match(r"^#\s*(\S+)", content)
    hid = hid_match.group(1) if hid_match else os.path.splitext(os.path.basename(path))[0]

    para = ""
    for line in content.splitlines()[1:]:
        line = line.strip()
        if not line:
            if para:
                break
            continue
        if line.startswith("|"):
            break
        para += (" " if para else "") + line
    if not para:
        return None

    tactic, tags = "", []
    table_row = re.search(r"\|\s*" + re.escape(hid) + r"\s*\|(.*)\|", content)
    if table_row:
        cols = [c.strip() for c in table_row.group(0).split("|")]
        if len(cols) >= 6:
            tactic = cols[3]
            tags = [t.strip() for t in cols[5].split() if t.startswith("#")]

    techs = list(dict.fromkeys(TECH_RE.findall(content)))
    return {
        "id": hid,
        "title": para[:140],
        "tactic": tactic,
        "technique": techs[0] if techs else "",
        "text": para,
        "category": category,
        "all_tactics": [tactic] if tactic else [],
        "all_techniques": techs,
        "tags": tags,
    }


def main():
    tmp_dir = tempfile.mkdtemp(prefix="hearth_repo_")
    try:
        print(f"Cloning {REPO_URL} ...")
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, tmp_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        results, skipped = [], []
        for category in CATEGORIES:
            for path in sorted(glob.glob(os.path.join(tmp_dir, category, "*.md"))):
                if os.path.basename(path) in SKIP_FILES:
                    skipped.append(path)
                    continue
                with open(path, encoding="utf-8") as f:
                    head = f.read(10)
                item = (
                    parse_frontmatter_file(path, category)
                    if head.startswith("---")
                    else parse_table_file(path, category)
                )
                if item:
                    results.append(item)
                else:
                    skipped.append(path)

        seen, deduped = set(), []
        for r in results:
            if r["id"] in seen:
                continue
            seen.add(r["id"])
            deduped.append(r)

        os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(deduped, f, indent=2)

        print(f"Wrote {len(deduped)} hypotheses to {os.path.abspath(OUT_PATH)}")
        if skipped:
            print(f"Skipped {len(skipped)} file(s) (no parseable hypothesis, e.g. the ARG easter egg).")
        print("\nNow run: docker compose run --rm kb-ingest")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
