"""Authenticated SOCmate UI gateway for THOS hunt and report workflows."""
from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import hmac
from html import escape
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sys
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from services.api import control_plane
from services.runtime_config import get_value, read_config


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "thos-ui",
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
logger = logging.getLogger(__name__)

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8200").rstrip("/")
ORCHESTRATOR_API_KEY = os.environ.get("ORCHESTRATOR_API_KEY", "thos_change_me_orchestrator_key")
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/data/reports"))
STATIC_DIR = Path(os.environ.get("UI_STATIC_DIR", "/app/static"))
_UPSTREAM_HEADERS = {"Authorization": f"Bearer {ORCHESTRATOR_API_KEY}"}


def _parse_accounts() -> list[tuple[str, str]]:
    raw = os.environ.get("CHATUI_USERS", "").strip()
    accounts: list[tuple[str, str]] = []
    if raw:
        for entry in raw.split(","):
            username, separator, password = entry.strip().partition(":")
            if separator and username and password:
                accounts.append((username, password))
            else:
                logger.warning("ignoring malformed CHATUI_USERS entry")
    else:
        username = os.environ.get("CHATUI_USERNAME", "analyst").strip() or "analyst"
        password = os.environ.get("CHATUI_PASSWORD", "thos_change_me")
        accounts.append((username, password))
    if not accounts:
        raise RuntimeError("no valid UI accounts configured")
    return accounts


UI_ACCOUNTS = _parse_accounts()
control_plane.seed_users(UI_ACCOUNTS)
SESSION_COOKIE = "thos_session"
SESSION_TTL_SECONDS = max(900, int(os.environ.get("CHATUI_SESSION_TTL_SECONDS", "43200")))
SESSION_SECURE_COOKIE = os.environ.get("CHATUI_SECURE_COOKIE", "0").strip().lower() in {"1", "true", "yes"}
SESSION_SECRET = os.environ.get("CHATUI_SESSION_SECRET", "").encode("utf-8")
if not SESSION_SECRET:
    SESSION_SECRET = hashlib.sha256(
        f"{ORCHESTRATOR_API_KEY}:{UI_ACCOUNTS[0][1]}:thos-ui-session".encode("utf-8")
    ).digest()
    logger.warning("CHATUI_SESSION_SECRET is unset; deriving a local session key from configured secrets")
app = FastAPI(title="THOS SOCmate UI", version="1.0.0", docs_url=None, redoc_url=None)


def _valid_account(supplied_user: str, supplied_password: str) -> str:
    user = control_plane.authenticate(supplied_user, supplied_password)
    return str(user.get("username", "")) if user else ""


def _session_token(username: str) -> str:
    payload = json.dumps(
        {"sub": username, "exp": int(datetime.now(timezone.utc).timestamp()) + SESSION_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(SESSION_SECRET, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _session_user(token: str) -> str:
    encoded, separator, supplied_signature = token.partition(".")
    if not separator:
        return ""
    expected = hmac.new(SESSION_SECRET, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied_signature, expected):
        return ""
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        username = str(payload.get("sub", ""))
        expires = int(payload.get("exp", 0))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if expires <= int(datetime.now(timezone.utc).timestamp()):
        return ""
    user = control_plane.get_user(username)
    return username if user and user.get("enabled", True) else ""


@app.middleware("http")
async def require_ui_auth(request: Request, call_next):
    public_path = (
        request.url.path in {"/", "/index.html", "/health", "/api/auth/login", "/api/auth/logout"}
        or request.url.path.startswith("/assets/")
    )
    if public_path:
        return await call_next(request)
    valid_user = _session_user(request.cookies.get(SESSION_COOKIE, ""))
    if not valid_user:
        return JSONResponse(status_code=401, content={"detail": "authentication required"})
    user = control_plane.get_user(valid_user) or {}
    request.state.analyst = valid_user
    request.state.display_name = user.get("display_name") or valid_user
    request.state.role = user.get("role", "Analyst")
    request.state.permissions = set(user.get("permissions", []))
    return await call_next(request)


class HuntRequest(BaseModel):
    hypothesis_id: str | None = None
    hypothesis_text: str | None = None
    hypothesis_tactic: str = ""
    hypothesis_technique: str = ""
    siem_type: str = "folder"
    log_source_path: str | None = None
    max_iterations: int | None = Field(default=None, ge=1, le=5)
    cover_style: str = Field(default="1", pattern="^[12]$")

    @model_validator(mode="after")
    def require_hypothesis(self):
        if not (self.hypothesis_id or "").strip() and not (self.hypothesis_text or "").strip():
            raise ValueError("hypothesis_id or hypothesis_text is required")
        return self


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


async def _upstream_json(method: str, path: str, **kwargs):
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
        response = await client.request(
            method,
            f"{ORCHESTRATOR_URL}{path}",
            headers=_UPSTREAM_HEADERS,
            **kwargs,
        )
    if response.is_error:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail or "orchestrator request failed")
    return response.json()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/auth/login")
async def login(credentials: LoginRequest):
    username = _valid_account(credentials.username, credentials.password)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user = control_plane.get_user(username) or {}
    response = JSONResponse({"analyst": username, **control_plane.public_user(user)})
    response.set_cookie(
        SESSION_COOKIE,
        _session_token(username),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_SECURE_COOKIE,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="strict")
    return response


@app.get("/api/session")
async def session(request: Request):
    return {
        "analyst": request.state.analyst,
        "display_name": request.state.display_name,
        "role": request.state.role,
        "permissions": sorted(request.state.permissions),
    }


@app.get("/api/hypotheses")
async def hypotheses(request: Request):
    control_plane.require_feature(request, "hunts")
    hearth, last_runs = await asyncio.gather(
        _upstream_json("GET", "/hypotheses"),
        _upstream_json("GET", "/hypotheses/last-runs"),
    )
    recent = {item.get("hypothesis_id"): item for item in last_runs}
    custom = read_config().get("custom_hypotheses", [])
    return [
        {**item, **({
            "last_ran_at": recent[item.get("id")].get("last_ran_at"),
            "last_run_status": recent[item.get("id")].get("status"),
        } if item.get("id") in recent else {})}
        for item in [*(hearth if isinstance(hearth, list) else []), *custom]
    ]


@app.get("/api/hunts/status")
async def hunt_status(request: Request):
    control_plane.require_feature(request, "hunts")
    try:
        return await _upstream_json("GET", "/hunt/status")
    except httpx.RequestError:
        # The UI polls during rolling restarts; an unavailable Orchestrator is
        # not an application error and must not flood the gateway logs.
        return {"active": False, "active_count": 0, "available": False}


@app.get("/api/hunts/history")
async def hunt_history(request: Request, limit: int = 100):
    control_plane.require_feature(request, "reports")
    return await _upstream_json("GET", f"/hunts?limit={max(1, min(limit, 500))}")


@app.get("/api/hunts/{hunt_id}/progress")
async def hunt_progress(hunt_id: str, request: Request):
    control_plane.require_feature(request, "hunts")
    return await _upstream_json("GET", f"/hunts/{hunt_id}/progress")


@app.post("/api/hunts/stream")
async def stream_hunt(hunt: HuntRequest, request: Request):
    control_plane.require_feature(request, "hunts")
    if not control_plane.is_active_telemetry_source(hunt.siem_type):
        raise HTTPException(status_code=422, detail="Telemetry source is not active; save and successfully test it in Settings")
    status = await _upstream_json("GET", "/hunt/status")
    if status.get("active"):
        raise HTTPException(status_code=409, detail="A hunt is already running. Wait for it to complete before starting another hypothesis.")
    payload = hunt.model_dump()
    if payload.get("max_iterations") is None:
        payload["max_iterations"] = max(1, min(5, int(get_value("general", "default_iterations", default=1))))
    payload["hunter_name"] = request.state.analyst

    async def relay() -> AsyncIterator[bytes]:
        timeout = httpx.Timeout(connect=10.0, read=900.0, write=30.0, pool=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "POST",
                    f"{ORCHESTRATOR_URL}/hunt/stream",
                    headers=_UPSTREAM_HEADERS,
                    json=payload,
                ) as response:
                    if response.is_error:
                        body = await response.aread()
                        yield (json.dumps({
                            "event": "error",
                            "error": body.decode("utf-8", errors="replace") or f"orchestrator returned {response.status_code}",
                        }) + "\n").encode()
                        return
                    async for chunk in response.aiter_bytes():
                        yield chunk
        except Exception as exc:  # noqa: BLE001 - converted to a stream event
            logger.exception("hunt stream proxy failed")
            yield (json.dumps({"event": "error", "error": str(exc)}) + "\n").encode()

    return StreamingResponse(relay(), media_type="application/x-ndjson")


def _safe_report(filename: str) -> Path:
    if not filename or Path(filename).name != filename or not filename.lower().endswith(".md"):
        raise HTTPException(status_code=404, detail="report not found")
    root = REPORTS_DIR.resolve()
    candidate = (root / filename).resolve()
    if candidate.parent != root or not candidate.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    return candidate


def _first_heading(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return re.sub(r"[*_`]", "", match.group(1)).strip()
    return fallback


def _hunt_id(markdown: str) -> str:
    patterns = (
        r"\*\*Hunt ID:?\*\*\s*[:|]?\s*`?([0-9a-fA-F-]{20,})",
        r"Hunt\s+`([0-9a-fA-F-]{20,})`",
    )
    for pattern in patterns:
        match = re.search(pattern, markdown)
        if match:
            return match.group(1)
    return ""


def _report_metadata(path: Path, content: str | None = None) -> dict:
    text = content if content is not None else path.read_text(encoding="utf-8", errors="replace")
    stat = path.stat()
    return {
        "filename": path.name,
        "title": _first_heading(text, path.stem.replace("_", " ")),
        "hunt_id": _hunt_id(text),
        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "size": stat.st_size,
    }


@app.get("/api/reports")
async def list_reports(request: Request):
    control_plane.require_feature(request, "reports")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    reports = [_report_metadata(path) for path in REPORTS_DIR.glob("*.md") if path.is_file()]
    return sorted(reports, key=lambda item: item["modified"], reverse=True)


@app.get("/api/reports/{filename}")
async def read_report(filename: str, request: Request):
    control_plane.require_feature(request, "reports")
    path = _safe_report(filename)
    content = path.read_text(encoding="utf-8", errors="replace")
    return {**_report_metadata(path, content), "content": content}


@app.get("/api/reports/{filename}/markdown")
async def download_markdown(filename: str, request: Request):
    control_plane.require_feature(request, "reports")
    path = _safe_report(filename)
    return Response(
        content=path.read_bytes(),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


def _register_fonts() -> tuple[str, str]:
    regular_path = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold_path = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    mono_path = Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
    if regular_path.is_file() and bold_path.is_file():
        if "THOSDejaVu" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("THOSDejaVu", str(regular_path)))
            pdfmetrics.registerFont(TTFont("THOSDejaVu-Bold", str(bold_path)))
            pdfmetrics.registerFontFamily("THOSDejaVu", normal="THOSDejaVu", bold="THOSDejaVu-Bold")
            if mono_path.is_file():
                pdfmetrics.registerFont(TTFont("THOSMono", str(mono_path)))
        return "THOSDejaVu", "THOSMono" if mono_path.is_file() else "Courier"
    return "Helvetica", "Courier"


def _inline_markdown(value: str) -> str:
    text = escape(value.strip())
    text = re.sub(r"`([^`]+)`", r'<font name="THOSMono" color="#4338ca">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__([^_]+)__", r"<b>\1</b>", text)
    text = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", text)
    text = re.sub(r"\[([^]]+)]\((https?://[^)]+)\)", r'<a href="\2" color="#4f46e5">\1</a>', text)
    return text


def _pdf_styles(font_name: str, mono_name: str):
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=sample["Title"], fontName=font_name, fontSize=22, leading=28, textColor=colors.HexColor("#101828"), alignment=TA_LEFT, spaceAfter=14),
        "h2": ParagraphStyle("H2", parent=sample["Heading2"], fontName=font_name, fontSize=15, leading=20, textColor=colors.HexColor("#172033"), spaceBefore=16, spaceAfter=8, borderColor=colors.HexColor("#dfe4ec"), borderWidth=0, borderPadding=(0, 0, 5, 0)),
        "h3": ParagraphStyle("H3", parent=sample["Heading3"], fontName=font_name, fontSize=11.5, leading=16, textColor=colors.HexColor("#25324a"), spaceBefore=11, spaceAfter=6),
        "body": ParagraphStyle("Body", parent=sample["BodyText"], fontName=font_name, fontSize=8.8, leading=13.5, textColor=colors.HexColor("#344054"), spaceAfter=7),
        "bullet": ParagraphStyle("Bullet", parent=sample["BodyText"], fontName=font_name, fontSize=8.6, leading=13, leftIndent=12, firstLineIndent=-8, bulletIndent=0, textColor=colors.HexColor("#344054"), spaceAfter=4),
        "quote": ParagraphStyle("Quote", parent=sample["BodyText"], fontName=font_name, fontSize=8.6, leading=13, leftIndent=12, rightIndent=8, borderColor=colors.HexColor("#818cf8"), borderWidth=2, borderPadding=7, backColor=colors.HexColor("#f5f7ff"), textColor=colors.HexColor("#475467"), spaceBefore=5, spaceAfter=8),
        "code": ParagraphStyle("Code", parent=sample["Code"], fontName=mono_name, fontSize=6.8, leading=9.5, leftIndent=7, rightIndent=7, borderPadding=8, backColor=colors.HexColor("#111827"), textColor=colors.HexColor("#e5e7eb"), spaceBefore=6, spaceAfter=9),
        "cell": ParagraphStyle("Cell", parent=sample["BodyText"], fontName=font_name, fontSize=6.8, leading=9.5, textColor=colors.HexColor("#344054")),
        "cell_head": ParagraphStyle("CellHead", parent=sample["BodyText"], fontName=font_name, fontSize=6.8, leading=9.5, textColor=colors.HexColor("#172033")),
    }


_TABLE_SEPARATOR = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$")


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _markdown_story(markdown: str, styles: dict) -> list:
    lines = markdown.replace("\r\n", "\n").split("\n")
    story: list = []
    paragraph: list[str] = []
    in_code = False
    code_lines: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            story.append(Paragraph(_inline_markdown(" ".join(part.strip() for part in paragraph)), styles["body"]))
            paragraph.clear()

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if stripped.startswith("```"):
            flush_paragraph()
            if in_code:
                story.append(Preformatted("\n".join(code_lines), styles["code"], maxLineLength=108))
                code_lines.clear()
                in_code = False
            else:
                in_code = True
            index += 1
            continue
        if in_code:
            code_lines.append(line)
            index += 1
            continue
        if index + 1 < len(lines) and "|" in stripped and _TABLE_SEPARATOR.match(lines[index + 1]):
            flush_paragraph()
            rows = [_table_cells(stripped)]
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                rows.append(_table_cells(lines[index]))
                index += 1
            column_count = max(len(row) for row in rows)
            normalized = [row + [""] * (column_count - len(row)) for row in rows]
            rendered = [
                [Paragraph(_inline_markdown(cell), styles["cell_head"] if row_index == 0 else styles["cell"]) for cell in row]
                for row_index, row in enumerate(normalized)
            ]
            usable_width = A4[0] - 36 * mm
            table = Table(rendered, colWidths=[usable_width / column_count] * column_count, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cfd6e2")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.extend([table, Spacer(1, 7)])
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            level = len(heading.group(1))
            style = styles["title"] if level == 1 else styles["h2"] if level == 2 else styles["h3"]
            story.append(Paragraph(_inline_markdown(heading.group(2)), style))
        elif re.match(r"^[-*_]{3,}$", stripped):
            flush_paragraph()
            story.append(Spacer(1, 5))
        elif stripped.startswith(">"):
            flush_paragraph()
            story.append(Paragraph(_inline_markdown(stripped.lstrip("> ")), styles["quote"]))
        elif re.match(r"^[-*+]\s+", stripped):
            flush_paragraph()
            story.append(Paragraph(_inline_markdown(re.sub(r"^[-*+]\s+", "", stripped)), styles["bullet"], bulletText="•"))
        elif re.match(r"^\d+[.)]\s+", stripped):
            flush_paragraph()
            number = re.match(r"^(\d+)[.)]", stripped).group(1)
            story.append(Paragraph(_inline_markdown(re.sub(r"^\d+[.)]\s+", "", stripped)), styles["bullet"], bulletText=f"{number}."))
        elif stripped == "":
            flush_paragraph()
        elif stripped == "<!-- pagebreak -->":
            flush_paragraph()
            story.append(PageBreak())
        else:
            paragraph.append(stripped)
        index += 1
    flush_paragraph()
    if code_lines:
        story.append(Preformatted("\n".join(code_lines), styles["code"], maxLineLength=108))
    return story


def _render_pdf(markdown: str, title: str, filename: str) -> bytes:
    font_name, mono_name = _register_fonts()
    styles = _pdf_styles(font_name, mono_name)
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=title,
        author="THOS Threat Hunting Operations",
        subject=filename,
    )

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFont(font_name, 7)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(18 * mm, A4[1] - 12 * mm, "THOS  /  VERIFIED HUNT REPORT")
        canvas.setStrokeColor(colors.HexColor("#dfe4ec"))
        canvas.line(18 * mm, A4[1] - 14 * mm, A4[0] - 18 * mm, A4[1] - 14 * mm)
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFillColor(colors.HexColor("#98a2b3"))
        canvas.drawString(18 * mm, 9 * mm, filename[:74])
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = _markdown_story(markdown, styles)
    if not story:
        story = [Paragraph("Empty report", styles["title"])]
    document.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return output.getvalue()


@app.get("/api/reports/{filename}/pdf")
async def download_pdf(filename: str, request: Request):
    control_plane.require_feature(request, "reports")
    path = _safe_report(filename)
    markdown = path.read_text(encoding="utf-8", errors="replace")
    title = _first_heading(markdown, path.stem)
    try:
        content = _render_pdf(markdown, title, path.name)
    except Exception as exc:  # noqa: BLE001 - PDF errors become a clean API response
        logger.exception("report PDF rendering failed")
        raise HTTPException(status_code=500, detail=f"could not render report PDF: {exc}") from exc
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{path.stem}.pdf"'},
    )


@app.on_event("startup")
async def _start_settings_scheduler():
    control_plane.start_scheduler()


@app.on_event("shutdown")
async def _stop_settings_scheduler():
    await control_plane.stop_scheduler()


app.include_router(control_plane.router)


if not STATIC_DIR.is_dir():
    logger.warning("UI static directory is missing: %s", STATIC_DIR)
else:
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
