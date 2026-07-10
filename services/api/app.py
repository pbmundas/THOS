"""
THOS Chat UI — the hunter's interaction surface.

A Gradio front-end over the orchestrator's FastAPI service. The hunter:
  1. Picks a HEARTH hypothesis (or types free-text hunting intent)
  2. Hits "Run Hunt" and watches each LangGraph node stream progress live
  3. Reads the AI's reasoning summary + generated markdown report
  4. Iterates — asks a follow-up, re-runs with a refined hypothesis, etc.

Phase 2+ extension point: replace the single "Run Hunt" button with a
true multi-turn agent loop (hunter asks a clarifying question mid-hunt,
UI calls a `/hunt/{id}/continue` endpoint against a paused LangGraph
checkpoint instead of always running start-to-finish).
"""
import datetime
import logging
import os
import json
import glob
import shutil
import sys
import httpx
import gradio as gr


# --- Structured logging ------------------------------------------------
# This service's Docker build (services/api/Dockerfile.chatui) copies
# only this single file into the image -- it has no access to the
# services.observability package that the orchestrator/MCP services
# share (see services/observability/logging_config.py for the version
# those use). Rather than restructure the chat-ui build to pull in the
# rest of the repo just for this, the same one JSON-line-per-log-event
# behavior is reproduced here directly: LOG_LEVEL-configurable, stdout,
# aggregator-ready -- so this service isn't the one place still doing
# unleveled, unstructured print().
class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "service": "thos-chat-ui",
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_JsonFormatter())
logging.getLogger().handlers.clear()
logging.getLogger().addHandler(_handler)
logging.getLogger().setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8200")
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/data/reports")
LOG_SOURCE_DIR = os.environ.get("LOG_SOURCE_DIR", "/data/log_sources")

# --- Auth -------------------------------------------------------------
# Two separate credentials, for two separate hops:
#  1. ORCHESTRATOR_API_KEY authenticates *this service* to the orchestrator
#     API (must match the orchestrator's own ORCHESTRATOR_API_KEY).
#  2. CHATUI_USERNAME/CHATUI_PASSWORD gate the browser-facing Gradio app
#     itself, so a hunter has to log in before reaching the UI at all —
#     previously anyone who could reach port 7860 could run hunts and read
#     every report with no login screen whatsoever.
_DEFAULT_ORCHESTRATOR_API_KEY = "thos_change_me_orchestrator_key"
ORCHESTRATOR_API_KEY = os.environ.get("ORCHESTRATOR_API_KEY", _DEFAULT_ORCHESTRATOR_API_KEY)
if ORCHESTRATOR_API_KEY == _DEFAULT_ORCHESTRATOR_API_KEY:
    logger.warning(
        "ORCHESTRATOR_API_KEY is unset, using the built-in default. Set a "
        "real secret (matching the orchestrator's ORCHESTRATOR_API_KEY) "
        "before exposing this UI beyond a trusted local dev network."
    )
_AUTH_HEADERS = {"Authorization": f"Bearer {ORCHESTRATOR_API_KEY}"}

CHATUI_USERNAME = os.environ.get("CHATUI_USERNAME", "")
CHATUI_PASSWORD = os.environ.get("CHATUI_PASSWORD", "")
CHATUI_USERS = os.environ.get("CHATUI_USERS", "")


def _parse_chatui_users(raw: str) -> list[tuple[str, str]]:
    """Parse CHATUI_USERS="alice:pw1,bob:pw2" into [(user, pass), ...].
    Lets a deploy define more than one hunter login without code changes.
    Malformed entries (missing ':', empty user/pass) are skipped with a
    warning rather than silently dropped or crashing the whole service."""
    pairs = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            logger.warning("skipping malformed CHATUI_USERS entry (missing ':'): %r", entry)
            continue
        user, _, pw = entry.partition(":")
        user, pw = user.strip(), pw.strip()
        if not user or not pw:
            logger.warning("skipping malformed CHATUI_USERS entry (empty user or password): %r", entry)
            continue
        pairs.append((user, pw))
    return pairs


if CHATUI_USERS:
    CHATUI_ACCOUNTS = _parse_chatui_users(CHATUI_USERS)
    if not CHATUI_ACCOUNTS:
        raise RuntimeError(
            "CHATUI_USERS was set but contained no valid 'user:pass' entries. "
            "Expected format: CHATUI_USERS=alice:pw1,bob:pw2"
        )
elif CHATUI_USERNAME and CHATUI_PASSWORD:
    CHATUI_ACCOUNTS = [(CHATUI_USERNAME, CHATUI_PASSWORD)]
else:
    logger.warning(
        "no CHATUI_USERS or CHATUI_USERNAME/CHATUI_PASSWORD set — falling "
        "back to 'analyst'/'thos_change_me'. Anyone who can reach port 7860 "
        "with those credentials can run hunts and read every report. Set "
        "real credentials before exposing this UI beyond a trusted local "
        "dev network."
    )
    CHATUI_ACCOUNTS = [("analyst", "thos_change_me")]

FOLDER_SIEM_VALUE = "folder"

NODE_LABELS = {
    "hypothesis": "🎯 Selecting hypothesis & MITRE context",
    "query_gen": "📝 Generating SIEM query",
    "siem_fetch": "📥 Fetching logs from SIEM",
    "log_processing": "🧹 Normalizing / deduplicating logs",
    "soc_tools": "🛠️ Running SOC tools (SIGMA/enrichment)",
    "reasoning": "🧠 Reasoning over evidence (Ollama)",
    "report": "📄 Writing markdown report",
}


def fetch_hypotheses():
    try:
        resp = httpx.get(f"{ORCHESTRATOR_URL}/hypotheses", headers=_AUTH_HEADERS, timeout=15)
        resp.raise_for_status()
        items = resp.json()
        return [f'{h["id"]} — {h["title"]}' for h in items]
    except Exception as e:  # noqa: BLE001
        return [f"(could not load hypotheses: {e})"]


def _extract_hypothesis_id(choice: str) -> str | None:
    if choice and " — " in choice:
        return choice.split(" — ", 1)[0]
    return None


def on_siem_type_change(siem_type):
    """Show the folder-path box + uploader only when 'Local Folder' is selected."""
    return gr.update(visible=(siem_type == FOLDER_SIEM_VALUE))


def upload_logs_to_folder(files, folder_path):
    """Copy uploaded files into the target log-source folder so the
    orchestrator's folder connector can parse them on the next hunt."""
    folder_path = folder_path or LOG_SOURCE_DIR
    os.makedirs(folder_path, exist_ok=True)
    if not files:
        return f"No files selected. Target folder: `{folder_path}`"
    copied = []
    for f in files:
        src = f.name if hasattr(f, "name") else f
        dest = os.path.join(folder_path, os.path.basename(src))
        try:
            shutil.copy(src, dest)
            copied.append(os.path.basename(dest))
        except Exception as e:  # noqa: BLE001
            copied.append(f"(failed: {os.path.basename(src)} — {e})")
    return f"Copied {len(copied)} file(s) to `{folder_path}`:\n\n" + "\n".join(f"- {c}" for c in copied)


def list_folder_files(folder_path):
    """Ask the orchestrator (which proxies to the mcp-server container,
    where the shared volume actually lives) what supported log files it
    currently sees in the folder."""
    folder_path = folder_path or LOG_SOURCE_DIR
    try:
        resp = httpx.get(f"{ORCHESTRATOR_URL}/log_sources", params={"folder": folder_path},
                          headers=_AUTH_HEADERS, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        count = data.get("count", 0)
        files = data.get("files", [])
        if count == 0:
            return (f"No supported log files found in `{folder_path}` yet.\n\n"
                     f"Supported types: evtx, log, syslog, csv, cef, json, ecs, xml, txt, pcap.")
        listing = "\n".join(f"- {name}" for name in files[:100])
        more = f"\n\n_...and {count - 100} more_" if count > 100 else ""
        return f"**{count} file(s) found in `{folder_path}`:**\n\n{listing}{more}"
    except Exception as e:  # noqa: BLE001
        return f"❌ Could not list files: {e}"


def run_hunt(message, history, hunter_name, siem_type, log_source_path, max_iterations):
    """Generator: streams live progress into the chat, then appends the final summary."""
    history = history or []
    hyp_id = _extract_hypothesis_id(message) if " — " in (message or "") else None
    hyp_text = message if not hyp_id else None

    history.append({"role": "user", "content": message})
    progress_lines = []
    history.append({"role": "assistant", "content": "Starting hunt..."})
    yield history, ""

    payload = {
        "hunter_name": hunter_name or "anonymous",
        "hypothesis_id": hyp_id,
        "hypothesis_text": hyp_text,
        "siem_type": siem_type,
        "log_source_path": log_source_path if siem_type == FOLDER_SIEM_VALUE else None,
        "max_iterations": int(max_iterations),
    }

    final_state = {}
    hunt_failed = False
    # A flat timeout=300 applies to connect/read/write/pool alike. The
    # orchestrator streams a line after each node completes, so the read
    # timer resets on every node — but a single slow node (reasoning, now
    # allowed up to 600s per Ollama call, and possibly repeated across
    # max_iterations loops) can legitimately take longer than 300s between
    # lines even though the hunt is still progressing fine server-side.
    # Connect/write/pool stay tight so a genuinely unreachable orchestrator
    # still fails fast; only the read timeout (gap between streamed lines)
    # is generous enough to cover one slow reasoning call.
    stream_timeout = httpx.Timeout(connect=10.0, read=900.0, write=30.0, pool=10.0)
    try:
        with httpx.stream("POST", f"{ORCHESTRATOR_URL}/hunt/stream", json=payload,
                           headers=_AUTH_HEADERS, timeout=stream_timeout) as resp:
            for line in resp.iter_lines():
                if not line:
                    continue
                evt = json.loads(line)
                if evt.get("event") == "hunt_started":
                    progress_lines.append(f"Hunt `{evt['hunt_id']}` started.")
                elif evt.get("event") == "node_complete":
                    label = NODE_LABELS.get(evt["node"], evt["node"])
                    progress_lines.append(label)
                elif evt.get("event") == "error":
                    progress_lines.append(f"❌ Error: {evt['error']}")
                    hunt_failed = True
                elif evt.get("event") == "hunt_complete":
                    final_state = evt.get("state", {})

                history[-1] = {"role": "assistant", "content": "\n".join(progress_lines)}
                yield history, ""
    except Exception as e:  # noqa: BLE001
        history[-1] = {"role": "assistant", "content": f"❌ Could not reach orchestrator: {e}"}
        yield history, ""
        return

    if hunt_failed or not final_state:
        # Keep the real error trail visible instead of papering over it
        # with a fake "Hunt complete" summary.
        history[-1] = {"role": "assistant", "content": "\n".join(progress_lines)}
        yield history, ""
        return

    summary = final_state.get("reasoning_summary", "(no summary produced)")
    findings = final_state.get("findings", "")
    recs = final_state.get("recommendations", "")
    report_path = final_state.get("report_path", "")

    final_msg = (
        f"**Hunt complete.**\n\n"
        f"**Summary:** {summary}\n\n"
        f"**Findings:**\n{findings}\n\n"
        f"**Recommendations:**\n{recs}\n\n"
        f"Report saved: `{report_path}`\n\n"
        f"_You can refine and re-run — e.g. ask for a narrower query, or type another hypothesis._"
    )
    history[-1] = {"role": "assistant", "content": final_msg}

    report_md = ""
    if report_path and os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_md = f.read()

    yield history, report_md


KB_SUPPORTED_TYPES = [".txt", ".md", ".markdown", ".csv", ".tsv", ".json",
                       ".log", ".html", ".htm", ".pdf", ".docx"]


def kb_upload_files(files):
    """Send each selected file to the orchestrator's /kb/upload endpoint,
    which forwards it to the upload_kb_document MCP tool for chunk+embed."""
    if not files:
        return "No files selected."
    lines = []
    for f in files:
        path = f.name if hasattr(f, "name") else f
        fname = os.path.basename(path)
        try:
            with open(path, "rb") as fh:
                content = fh.read()
            resp = httpx.post(
                f"{ORCHESTRATOR_URL}/kb/upload",
                files={"file": (fname, content)},
                headers=_AUTH_HEADERS, timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("error"):
                lines.append(f"❌ {fname}: {data['error']}")
            else:
                lines.append(
                    f"✅ {data.get('filename', fname)} — "
                    f"{data.get('chunk_count', '?')} chunk(s) ingested "
                    f"(doc_id: `{data.get('doc_id', '?')}`)"
                )
        except Exception as e:  # noqa: BLE001
            lines.append(f"❌ {fname}: {e}")
    return "\n".join(lines)


def kb_list_documents():
    try:
        resp = httpx.get(f"{ORCHESTRATOR_URL}/kb/documents", headers=_AUTH_HEADERS, timeout=15)
        resp.raise_for_status()
        docs = resp.json()
        if not docs:
            return "_No documents ingested yet._", []
        rows = [[d.get("doc_id", ""), d.get("filename", ""), d.get("chunk_count", 0),
                  d.get("content_type", ""), d.get("ingested_at", "")] for d in docs]
        return f"**{len(docs)} document(s) in the knowledge base:**", rows
    except Exception as e:  # noqa: BLE001
        return f"❌ Could not list documents: {e}", []


def kb_delete_document(doc_id):
    doc_id = (doc_id or "").strip()
    if not doc_id:
        return "Enter a `doc_id` to delete (copy one from the table above)."
    try:
        resp = httpx.delete(f"{ORCHESTRATOR_URL}/kb/documents/{doc_id}", headers=_AUTH_HEADERS, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("deleted"):
            return f"🗑️ Deleted `{doc_id}` ({data.get('chunks_removed', 0)} chunk(s))."
        return f"❌ {data.get('error', 'document not found')}"
    except Exception as e:  # noqa: BLE001
        return f"❌ Could not delete: {e}"


def kb_search(query, n_results):
    query = (query or "").strip()
    if not query:
        return "_Type a query above and click Search._"
    try:
        resp = httpx.get(
            f"{ORCHESTRATOR_URL}/kb/search",
            params={"query": query, "n_results": int(n_results)},
            headers=_AUTH_HEADERS, timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json()
        if not hits:
            return "_No matches._"
        blocks = []
        for h in hits:
            meta = h.get("meta", {}) or {}
            text = (h.get("text") or "")[:800]
            blocks.append(
                f"**{meta.get('filename', '?')}** "
                f"(chunk {meta.get('chunk_index', '?')}/{meta.get('chunk_count', '?')})\n\n"
                f"{text}\n\n---"
            )
        return "\n".join(blocks)
    except Exception as e:  # noqa: BLE001
        return f"❌ Search failed: {e}"


def list_reports():
    if not os.path.isdir(REPORTS_DIR):
        return []
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.md")), reverse=True)
    return files


def load_report(path):
    if not path or not os.path.exists(path):
        return "(select a report)"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


with gr.Blocks(title="THOS — AI Threat Hunting") as demo:
    gr.Markdown(
        "# 🔥 THOS — On-Prem AI Threat Hunting\n"
        "Ollama (Qwen) + LangGraph + FastMCP + RAG, fully on-prem.\n"
        "Pick a hypothesis below (or type free-text hunting intent) and run a hunt."
    )

    with gr.Tab("Hunt"):
        with gr.Row():
            hunter_name = gr.Textbox(label="Hunter name", value="analyst-1", scale=1)
            siem_type = gr.Dropdown(
                label="Target SIEM",
                choices=["mock", "splunk", "qradar", "logrhythm", FOLDER_SIEM_VALUE],
                value="mock", scale=1,
            )
            max_iterations = gr.Slider(label="Max reasoning iterations", minimum=1, maximum=5, value=3, step=1, scale=1)

        with gr.Group(visible=False) as folder_group:
            gr.Markdown(
                "**Local Folder log source** — point at a directory of raw log "
                "artifacts (evtx, log, syslog, csv, CEF, json, ECS, xml, txt, pcap). "
                "Every supported file is parsed and the selected hypothesis is run "
                "against the parsed records."
            )
            with gr.Row():
                log_source_path = gr.Textbox(
                    label="Log folder path (on the server)",
                    value=LOG_SOURCE_DIR, scale=2,
                )
                list_files_btn = gr.Button("🔍 List files in folder", size="sm", scale=1)
            file_upload = gr.File(
                label="...or upload log files here (copied into the folder above)",
                file_count="multiple",
                file_types=[".evtx", ".log", ".syslog", ".csv", ".cef", ".json",
                            ".ecs", ".ndjson", ".jsonl", ".xml", ".txt", ".pcap", ".pcapng"],
            )
            upload_btn = gr.Button("⬆️ Upload to folder", size="sm")
            folder_status = gr.Markdown(value="")

        hyp_dropdown = gr.Dropdown(label="HEARTH hypotheses (click to insert into chat box)", choices=[], interactive=True)
        refresh_btn = gr.Button("🔄 Load hypotheses from HEARTH", size="sm")

        chatbot = gr.Chatbot(label="Hunt conversation", height=420)
        msg_box = gr.Textbox(
            label="Hunting intent / hypothesis",
            placeholder="e.g. 'H-002 — Anomalous Outbound DNS Volume' or type your own hunting intent...",
        )
        report_view = gr.Markdown(label="Latest report", value="_Run a hunt to see the generated report here._")

        siem_type.change(
            fn=on_siem_type_change, inputs=siem_type,
            outputs=folder_group,
        )
        upload_btn.click(fn=upload_logs_to_folder, inputs=[file_upload, log_source_path], outputs=folder_status)
        list_files_btn.click(fn=list_folder_files, inputs=log_source_path, outputs=folder_status)

        refresh_btn.click(fn=lambda: gr.update(choices=fetch_hypotheses()), outputs=hyp_dropdown)
        hyp_dropdown.change(fn=lambda x: x, inputs=hyp_dropdown, outputs=msg_box)
        msg_box.submit(
            fn=run_hunt,
            inputs=[msg_box, chatbot, hunter_name, siem_type, log_source_path, max_iterations],
            outputs=[chatbot, report_view],
        ).then(lambda: "", outputs=msg_box)

    with gr.Tab("Knowledge Base"):
        gr.Markdown(
            "Upload reference material — playbooks, IR runbooks, threat-intel "
            "reports, vendor advisories, past hunt write-ups — and it's "
            "automatically chunked and embedded so it becomes semantically "
            "searchable, similar to a workspace knowledge base in AnythingLLM. "
            "This is separate from the log-file uploader on the Hunt tab.\n\n"
            f"**Supported types:** {', '.join(KB_SUPPORTED_TYPES)}"
        )
        kb_file_upload = gr.File(
            label="Upload documents", file_count="multiple", file_types=KB_SUPPORTED_TYPES,
        )
        kb_upload_btn = gr.Button("⬆️ Ingest into knowledge base")
        kb_upload_status = gr.Markdown(value="")

        gr.Markdown("### Ingested documents")
        kb_refresh_btn = gr.Button("🔄 Refresh document list", size="sm")
        kb_list_status = gr.Markdown(value="")
        kb_table = gr.Dataframe(
            headers=["doc_id", "filename", "chunks", "type", "ingested_at"],
            interactive=False, wrap=True,
        )
        with gr.Row():
            kb_delete_id = gr.Textbox(label="doc_id to delete", scale=3)
            kb_delete_btn = gr.Button("🗑️ Delete", size="sm", scale=1)
        kb_delete_status = gr.Markdown(value="")

        gr.Markdown("### Test semantic search")
        with gr.Row():
            kb_query = gr.Textbox(label="Query", scale=3)
            kb_n_results = gr.Slider(label="Results", minimum=1, maximum=10, value=5, step=1, scale=1)
        kb_search_btn = gr.Button("🔍 Search")
        kb_search_results = gr.Markdown(value="")

        kb_upload_btn.click(
            fn=kb_upload_files, inputs=kb_file_upload, outputs=kb_upload_status,
        ).then(fn=kb_list_documents, outputs=[kb_list_status, kb_table])
        kb_refresh_btn.click(fn=kb_list_documents, outputs=[kb_list_status, kb_table])
        kb_delete_btn.click(
            fn=kb_delete_document, inputs=kb_delete_id, outputs=kb_delete_status,
        ).then(fn=kb_list_documents, outputs=[kb_list_status, kb_table])
        kb_search_btn.click(fn=kb_search, inputs=[kb_query, kb_n_results], outputs=kb_search_results)

    with gr.Tab("Report Browser"):
        gr.Markdown("Browse every markdown report ever generated by the platform.")
        report_refresh = gr.Button("🔄 Refresh report list")
        report_dropdown = gr.Dropdown(label="Reports", choices=[])
        report_content = gr.Markdown(value="_select a report_")

        report_refresh.click(fn=lambda: gr.update(choices=list_reports()), outputs=report_dropdown)
        report_dropdown.change(fn=load_report, inputs=report_dropdown, outputs=report_content)

    demo.load(fn=lambda: gr.update(choices=fetch_hypotheses()), outputs=hyp_dropdown)
    demo.load(fn=lambda: gr.update(choices=list_reports()), outputs=report_dropdown)
    demo.load(fn=kb_list_documents, outputs=[kb_list_status, kb_table])


if __name__ == "__main__":
    # `auth` puts a login page in front of the entire Gradio app — without
    # it, anyone who can reach port 7860 could run hunts and read every
    # report with no credential at all. Passing a list of (user, pass)
    # pairs (rather than a single pair) lets more than one hunter log in
    # with their own credentials.
    demo.queue().launch(
        server_name="0.0.0.0",
        server_port=7860,
        auth=CHATUI_ACCOUNTS,
        auth_message="THOS — sign in to run hunts and view reports.",
    )
