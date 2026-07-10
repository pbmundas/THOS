"""
Shared HEARTH fetch/parse logic.

Downloads the current https://github.com/THORCollective/HEARTH repository
as a tarball (no `git` binary required — just an HTTPS call, so this works
from any container with outbound internet access) and converts every
Flames/Embers/Alchemy hypothesis markdown file into the flat dict shape
used throughout THOS (id/title/tactic/technique/text/...).

Used by:
  - services/knowledge/ingest_knowledge_base.py  (automatic refresh on
    every `docker compose up` via the kb-ingest service)
  - services/api/server.py's `refresh_hearth_hypotheses` MCP tool (on-demand
    refresh, callable by the LangGraph orchestrator or a hunter mid-session)

Fully offline / air-gapped environments: if the fetch fails (no route to
github.com), callers should fall back to whatever's already ingested/cached
locally rather than hard-failing — see ingest_hearth()'s fallback logic.
"""
import io
import re
import tarfile

import httpx
import yaml

from services.observability.retry import sync_retry

REPO_TARBALL_URL = "https://codeload.github.com/THORCollective/HEARTH/tar.gz/refs/heads/main"
CATEGORIES = ("Flames", "Embers", "Alchemy")
SKIP_FILES = {"secret.md"}  # THOR Collective's ARG/puzzle easter egg, not a real hypothesis
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _parse_frontmatter(text: str, category: str, fallback_id: str) -> dict | None:
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        return None
    fm = yaml.safe_load(m.group(1)) or {}
    hid = str(fm.get("id") or fallback_id)
    title = (fm.get("hypothesis") or "").strip().replace("\n", " ")
    if not title:
        return None
    tactics = fm.get("tactics") or []
    techniques = fm.get("techniques") or []
    body_text = title
    if fm.get("notes"):
        body_text = f"{title} {fm['notes']}".strip()
    return {
        "id": hid,
        "title": title[:140],
        "tactic": tactics[0] if tactics else "",
        "technique": techniques[0] if techniques else "",
        "text": body_text,
        "category": category,
        "all_tactics": tactics,
        "all_techniques": techniques,
        "tags": fm.get("tags") or [],
    }


def _parse_table(text: str, category: str, fallback_id: str) -> dict | None:
    """Older-format files: '# H180' heading + a markdown table + prose body,
    instead of YAML frontmatter."""
    hid_match = re.match(r"^#\s*(\S+)", text)
    hid = hid_match.group(1) if hid_match else fallback_id

    para = ""
    for line in text.splitlines()[1:]:
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
    table_row = re.search(r"\|\s*" + re.escape(hid) + r"\s*\|(.*)\|", text)
    if table_row:
        cols = [c.strip() for c in table_row.group(0).split("|")]
        if len(cols) >= 6:
            tactic = cols[3]
            tags = [t.strip() for t in cols[5].split() if t.startswith("#")]

    techs = list(dict.fromkeys(TECH_RE.findall(text)))
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


def fetch_and_parse_hearth(timeout: float = 30.0) -> list[dict]:
    """Download the live HEARTH repo and return a deduped list of hypothesis
    dicts. Raises on network failure — callers decide how to fall back."""
    resp = sync_retry(
        httpx.get, REPO_TARBALL_URL, timeout=timeout, follow_redirects=True,
        what="hearth_fetch (GitHub tarball)",
    )
    resp.raise_for_status()

    results = []
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # paths look like "HEARTH-main/Flames/H001.md"
            parts = member.name.split("/", 2)
            if len(parts) < 3:
                continue
            category, filename = parts[1], parts[2]
            if category not in CATEGORIES or not filename.endswith(".md"):
                continue
            if filename in SKIP_FILES:
                continue
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            content = fileobj.read().decode("utf-8", errors="replace")
            fallback_id = filename[:-3]
            item = (
                _parse_frontmatter(content, category, fallback_id)
                if content.startswith("---")
                else _parse_table(content, category, fallback_id)
            )
            if item:
                results.append(item)

    seen, deduped = set(), []
    for r in results:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        deduped.append(r)
    return deduped
