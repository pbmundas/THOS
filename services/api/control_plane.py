"""Governed settings, scheduling, RAG, users, and chat APIs for the UI gateway."""
from __future__ import annotations

import asyncio
import csv
import hashlib
import hmac
import logging
import io
import os
from pathlib import Path
import re
import secrets
import time as time_module
from datetime import datetime, timedelta
from typing import Any
import uuid

import httpx
import yaml
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from services.runtime_config import read_config, write_config


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8200").rstrip("/")
ORCHESTRATOR_API_KEY = os.environ.get("ORCHESTRATOR_API_KEY", "thos_change_me_orchestrator_key")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
SIGMAHQ_DIR = Path(os.environ.get("SIGMAHQ_UI_RULES_DIR", "/data/sigmahq"))
SIGMA_LOCAL_DIR = Path(os.environ.get("SIGMA_LOCAL_UI_RULES_DIR", "/data/sigma-local"))
_UPSTREAM_HEADERS = {"Authorization": f"Bearer {ORCHESTRATOR_API_KEY}"}
ALL_FEATURES = ("hunts", "forensics", "reports", "chat", "knowledge", "settings")
FULL_UI_ROLES = {"Admin", "SME"}
EXPERT_FEATURES = ("hunts", "forensics", "reports", "chat", "knowledge")
AVATAR_DIR = Path(os.environ.get(
    "THOS_AVATAR_DIR",
    str(Path(os.environ.get("THOS_RUNTIME_CONFIG", "/data/runtime/config.json")).parent / "avatars"),
))
_scheduler_task: asyncio.Task | None = None
_schema_refresh_task: asyncio.Task | None = None
if hasattr(time_module, "tzset"):
    time_module.tzset()


def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex(), digest.hex()


def seed_users(accounts: list[tuple[str, str]]) -> None:
    config = read_config()
    if config.get("users"):
        changed = False
        for user in config["users"]:
            if user.get("role") == "Analyst":
                user["role"] = "Expert"
                user["permissions"] = list(EXPERT_FEATURES)
                changed = True
            if "email" not in user:
                user["email"] = ""
                changed = True
        if not any(user.get("role") == "Admin" for user in config["users"]):
            owner = next((user for user in config["users"] if user.get("role") == "SME"), config["users"][0])
            owner["role"] = "Admin"
            owner["permissions"] = list(ALL_FEATURES)
            changed = True
        if changed:
            write_config(config)
        return
    users = []
    for index, (username, password) in enumerate(accounts):
        salt, password_hash = _hash_password(password)
        role = "Admin" if index == 0 else "Expert"
        users.append({
            "username": username,
            "display_name": username,
            "role": role,
            "permissions": list(ALL_FEATURES if role == "Admin" else EXPERT_FEATURES),
            "email": "",
            "salt": salt,
            "password_hash": password_hash,
            "enabled": True,
            "created_at": datetime.now().astimezone().isoformat(),
        })
    config["users"] = users
    write_config(config)


def get_user(username: str) -> dict[str, Any] | None:
    for user in read_config().get("users", []):
        if hmac.compare_digest(str(user.get("username", "")), username):
            return user
    return None


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    user = get_user(username)
    if not user or not user.get("enabled", True):
        return None
    _, supplied = _hash_password(password, str(user.get("salt", "")))
    return user if hmac.compare_digest(supplied, str(user.get("password_hash", ""))) else None


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user.get("username"),
        "display_name": user.get("display_name") or user.get("username"),
        "role": user.get("role", "Expert"),
        "permissions": user.get("permissions", []),
        "email": user.get("email", ""),
        "avatar_url": f"/api/account/avatar/{user.get('username')}" if user.get("avatar_file") else "",
        "enabled": bool(user.get("enabled", True)),
        "created_at": user.get("created_at", ""),
    }


def require_feature(
    request: Request, feature: str, *, sme_only: bool = False, admin_only: bool = False,
) -> None:
    if admin_only and request.state.role != "Admin":
        raise HTTPException(status_code=403, detail="Administrator access is required")
    if sme_only and request.state.role not in FULL_UI_ROLES:
        raise HTTPException(status_code=403, detail="SME or administrator access is required")
    if request.state.role in FULL_UI_ROLES:
        return
    if feature not in request.state.permissions:
        raise HTTPException(status_code=403, detail=f"Your role does not permit {feature}")


def _validated_email(value: str) -> str:
    email = value.strip().lower()
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return email


async def _upstream(method: str, path: str, **kwargs):
    timeout = kwargs.pop("timeout", httpx.Timeout(90.0, connect=10.0))
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(method, f"{ORCHESTRATOR_URL}{path}", headers=_UPSTREAM_HEADERS, **kwargs)
    if response.is_error:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail or "upstream request failed")
    return response.json()


class GeneralSettings(BaseModel):
    default_model: str = ""
    default_iterations: int = Field(default=1, ge=1, le=5)
    default_siem: str = Field(default="folder", pattern="^(folder|wazuh|logrhythm|splunk|qradar)$")


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    display_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=10, max_length=512)
    email: str = Field(default="", max_length=254)
    role: str = Field(pattern="^(Admin|SME|Expert)$")
    permissions: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    password: str | None = Field(default=None, min_length=10, max_length=512)
    email: str | None = Field(default=None, max_length=254)
    role: str | None = Field(default=None, pattern="^(Admin|SME|Expert)$")
    permissions: list[str] | None = None
    enabled: bool | None = None


class SiemSettings(BaseModel):
    settings: dict[str, str | int | bool] = Field(default_factory=dict)
    field_mapping: dict[str, str] = Field(default_factory=dict)


class RuleToggle(BaseModel):
    enabled: bool


class ScheduleRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=256)
    target_ids: list[str] = Field(default_factory=list, max_length=500)
    title: str = Field(default="", max_length=500)
    schedule_scope: str = Field(default="individual", pattern="^(individual|severity)$")
    severity: str | None = Field(default=None, pattern="^(all|low|medium|high|critical)$")
    time: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    frequency: str = Field(default="daily", pattern="^(minutes|hourly|daily)$")
    interval: int = Field(default=1, ge=1, le=59)
    days: list[int] = Field(default_factory=lambda: list(range(7)))
    enabled: bool = True
    siem_type: str = Field(default="mock", pattern="^(mock|folder|wazuh|logrhythm|splunk|qradar)$")
    log_source_path: str | None = None


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=16_000)
    conversation_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class ChatConversationCreate(BaseModel):
    title: str = Field(default="New conversation", max_length=120)


class HypothesisCreate(BaseModel):
    title: str = Field(min_length=8, max_length=300)
    text: str = Field(min_length=20, max_length=16_000)
    tactic: str = Field(min_length=2, max_length=120)
    technique: str = Field(default="", max_length=32, pattern=r"^(?:T\d{4}(?:\.\d{3})?)?$")
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class AccountProfileUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)
    email: str = Field(default="", max_length=254)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=10, max_length=512)


class IOCSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    kind: str = Field(default="remote", pattern="^(remote|local)$")
    location: str = Field(min_length=1, max_length=4096)
    confidence: str = Field(default="medium", pattern="^(low|medium|high)$")
    enabled: bool = True
    time: str = Field(default="00:00", pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    frequency: str = Field(default="daily", pattern="^(minutes|hourly|daily)$")
    interval: int = Field(default=1, ge=1, le=59)
    days: list[int] = Field(default_factory=lambda: list(range(7)))


SIEM_SCHEMAS = {
    "wazuh": [
        ("WAZUH_INDEXER_URL", "Indexer URL", "url", True),
        ("WAZUH_INDEXER_USERNAME", "Username", "text", True),
        ("WAZUH_INDEXER_PASSWORD", "Password", "password", True),
        ("WAZUH_INDEX_SOURCE", "Index source (alerts/archives/both)", "text", False),
        ("WAZUH_VERIFY_SSL", "Verify TLS (1/0)", "text", False),
        ("WAZUH_LOOKBACK_MINUTES", "Lookback minutes", "number", False),
    ],
    "logrhythm": [
        ("LOGRHYTHM_BASE_URL", "Search API URL", "url", True),
        ("LOGRHYTHM_API_TOKEN", "API token", "password", True),
        ("LOGRHYTHM_VERIFY_SSL", "Verify TLS (1/0)", "text", False),
        ("LOGRHYTHM_LOOKBACK_MINUTES", "Lookback minutes", "number", False),
    ],
    "splunk": [
        ("SPLUNK_BASE_URL", "Management API URL", "url", True),
        ("SPLUNK_TOKEN", "Bearer token", "password", True),
        ("SPLUNK_VERIFY_SSL", "Verify TLS (1/0)", "text", False),
        ("SPLUNK_LOOKBACK", "Earliest time", "text", False),
    ],
    "qradar": [
        ("QRADAR_BASE_URL", "Console URL", "url", True),
        ("QRADAR_TOKEN", "Authorized service token", "password", True),
        ("QRADAR_VERIFY_SSL", "Verify TLS (1/0)", "text", False),
        ("QRADAR_API_VERSION", "API version", "text", False),
        ("QRADAR_LOOKBACK_MINUTES", "Lookback minutes", "number", False),
    ],
    "folder": [("LOG_SOURCE_DIR", "Server log folder", "text", True)],
    "mock": [],
}
SECRET_FIELDS = {name for fields in SIEM_SCHEMAS.values() for name, _label, kind, _required in fields if kind == "password"}
TELEMETRY_LABELS = {
    "folder": "Local folder", "wazuh": "Wazuh", "logrhythm": "LogRhythm",
    "splunk": "Splunk", "qradar": "QRadar",
}


def telemetry_sources(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return only sources safe to offer to analysts.

    Folder-backed evidence is always available. API-backed SIEMs become active
    only after the most recently saved connection details pass a live test.
    """
    config = config or read_config()
    folder = {"id": "folder", "label": TELEMETRY_LABELS["folder"], "tested_at": "built-in"}
    live_items = []
    for siem_type in ("wazuh", "logrhythm", "splunk", "qradar"):
        entry = config.get("siem", {}).get(siem_type, {})
        if entry.get("connection_status") == "connected":
            live_items.append({
                "id": siem_type,
                "label": TELEMETRY_LABELS[siem_type],
                "tested_at": entry.get("connection_tested_at", ""),
            })
    # Live, connection-tested SIEMs are primary. The built-in evidence folder
    # remains available as a secondary fallback and is primary only when no
    # live SIEM has passed its connection test.
    items = [*live_items, folder] if live_items else [folder]
    active_ids = {item["id"] for item in items}
    preferred = str(config.get("general", {}).get("default_siem", "folder"))
    if live_items and preferred == "folder":
        preferred = live_items[0]["id"]
    return {"items": items, "default": preferred if preferred in active_ids else items[0]["id"]}


def is_active_telemetry_source(siem_type: str, config: dict[str, Any] | None = None) -> bool:
    return siem_type in {item["id"] for item in telemetry_sources(config)["items"]}


@router.get("/telemetry-sources")
async def list_active_telemetry_sources(request: Request):
    return telemetry_sources()


@router.get("/settings/general")
async def general_settings(request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    return {
        "default_model": config["models"].get("default_model", ""),
        "default_iterations": config["general"].get("default_iterations", 1),
        "default_siem": telemetry_sources(config)["default"],
        "timezone": os.environ.get("TZ") or str(datetime.now().astimezone().tzinfo),
    }


@router.put("/settings/general")
async def save_general(settings: GeneralSettings, request: Request):
    require_feature(request, "settings", sme_only=True)
    models = await available_models(request)
    names = {item["name"] for item in models["models"]}
    if settings.default_model and settings.default_model not in names:
        raise HTTPException(status_code=422, detail="Select a model currently available in Ollama")
    config = read_config()
    if not is_active_telemetry_source(settings.default_siem, config):
        raise HTTPException(status_code=422, detail="The default telemetry source must be connected and successfully tested")
    config["models"]["default_model"] = settings.default_model
    config["general"].update({
        "default_iterations": settings.default_iterations,
        "default_siem": settings.default_siem,
    })
    write_config(config)
    return await general_settings(request)


@router.get("/settings/models")
async def available_models(request: Request):
    require_feature(request, "settings", sme_only=True)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Could not list Ollama models: {exc}") from exc
    return {
        "models": [
            {"name": item.get("name") or item.get("model"), "size": item.get("size", 0), "modified_at": item.get("modified_at", "")}
            for item in models
        ],
        "default_model": read_config()["models"].get("default_model", ""),
    }


@router.get("/settings/users")
async def list_users(request: Request):
    require_feature(request, "settings", admin_only=True)
    return [public_user(user) for user in read_config().get("users", [])]


@router.get("/account")
async def account_profile(request: Request):
    user = get_user(request.state.analyst)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    return public_user(user)


@router.put("/account")
async def update_account_profile(payload: AccountProfileUpdate, request: Request):
    config = read_config()
    user = next((item for item in config.get("users", []) if item.get("username") == request.state.analyst), None)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    user["display_name"] = payload.display_name.strip()
    user["email"] = _validated_email(payload.email)
    write_config(config)
    return public_user(user)


@router.put("/account/password")
async def change_account_password(payload: PasswordChange, request: Request):
    if not authenticate(request.state.analyst, payload.current_password):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    config = read_config()
    user = next((item for item in config.get("users", []) if item.get("username") == request.state.analyst), None)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    user["salt"], user["password_hash"] = _hash_password(payload.new_password)
    write_config(config)
    return {"changed": True}


@router.post("/account/avatar")
async def upload_account_avatar(request: Request, file: UploadFile = File(...)):
    content = await file.read(2_000_001)
    await file.close()
    if not content or len(content) > 2_000_000:
        raise HTTPException(status_code=413, detail="Avatar must be a non-empty image no larger than 2 MB")
    signatures = (
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"\xff\xd8\xff", ".jpg"),
        (b"GIF87a", ".gif"),
        (b"GIF89a", ".gif"),
    )
    extension = next((suffix for signature, suffix in signatures if content.startswith(signature)), "")
    if not extension and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        extension = ".webp"
    if not extension:
        raise HTTPException(status_code=422, detail="Avatar must be PNG, JPEG, GIF, or WebP")
    safe_username = re.sub(r"[^A-Za-z0-9_.-]", "_", request.state.analyst)[:64]
    AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    target = (AVATAR_DIR / f"{safe_username}{extension}").resolve()
    if target.parent != AVATAR_DIR.resolve():
        raise HTTPException(status_code=422, detail="Invalid avatar path")
    temp = AVATAR_DIR / f".{safe_username}.{uuid.uuid4().hex}.tmp"
    temp.write_bytes(content)
    temp.replace(target)
    config = read_config()
    user = next((item for item in config.get("users", []) if item.get("username") == request.state.analyst), None)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    prior = user.get("avatar_file")
    user["avatar_file"] = target.name
    write_config(config)
    if prior and prior != target.name:
        old = (AVATAR_DIR / Path(str(prior)).name).resolve()
        if old.parent == AVATAR_DIR.resolve() and old.is_file():
            old.unlink()
    return public_user(user)


@router.get("/account/avatar/{username}")
async def account_avatar(username: str, request: Request):
    user = get_user(username)
    if not user or not user.get("avatar_file"):
        raise HTTPException(status_code=404, detail="Avatar not found")
    root = AVATAR_DIR.resolve()
    path = (root / Path(str(user["avatar_file"])).name).resolve()
    if path.parent != root or not path.is_file():
        raise HTTPException(status_code=404, detail="Avatar not found")
    media = {
        ".png": "image/png", ".jpg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    }.get(path.suffix.lower(), "application/octet-stream")
    return FileResponse(path, media_type=media, headers={"Cache-Control": "private, max-age=300"})


@router.get("/settings/hypotheses")
async def list_custom_hypotheses(request: Request):
    require_feature(request, "settings", sme_only=True)
    return read_config().get("custom_hypotheses", [])


@router.post("/settings/hypotheses", status_code=201)
async def create_custom_hypothesis(payload: HypothesisCreate, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    existing = config.setdefault("custom_hypotheses", [])
    sequence = max([
        int(str(item.get("id", "C0"))[1:])
        for item in existing
        if str(item.get("id", "")).startswith("C") and str(item.get("id", ""))[1:].isdigit()
    ] or [0]) + 1
    item = {
        "id": f"C{sequence:03d}",
        "title": payload.title.strip(),
        "text": payload.text.strip(),
        "tactic": payload.tactic.strip(),
        "technique": payload.technique.strip(),
        "severity": payload.severity,
        "category": "Custom",
        "custom": True,
        "created_by": request.state.analyst,
        "created_at": datetime.now().astimezone().isoformat(),
    }
    existing.append(item)
    write_config(config)
    return item


@router.delete("/settings/hypotheses/{hypothesis_id}")
async def delete_custom_hypothesis(hypothesis_id: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    existing = config.setdefault("custom_hypotheses", [])
    before = len(existing)
    existing[:] = [item for item in existing if item.get("id") != hypothesis_id]
    if len(existing) == before:
        raise HTTPException(status_code=404, detail="Custom hypothesis not found")
    write_config(config)
    return {"deleted": True, "hypothesis_id": hypothesis_id}


@router.post("/settings/users", status_code=201)
async def create_user(payload: UserCreate, request: Request):
    require_feature(request, "settings", admin_only=True)
    config = read_config()
    if any(user.get("username", "").lower() == payload.username.lower() for user in config["users"]):
        raise HTTPException(status_code=409, detail="Username already exists")
    permissions = (
        list(ALL_FEATURES)
        if payload.role in FULL_UI_ROLES
        else sorted(set(payload.permissions or EXPERT_FEATURES) & set(EXPERT_FEATURES))
    )
    salt, password_hash = _hash_password(payload.password)
    user = {
        "username": payload.username,
        "display_name": payload.display_name,
        "email": _validated_email(payload.email),
        "role": payload.role,
        "permissions": permissions,
        "salt": salt,
        "password_hash": password_hash,
        "enabled": True,
        "created_at": datetime.now().astimezone().isoformat(),
    }
    config["users"].append(user)
    write_config(config)
    return public_user(user)


@router.put("/settings/users/{username}")
async def update_user(username: str, payload: UserUpdate, request: Request):
    require_feature(request, "settings", admin_only=True)
    config = read_config()
    user = next((item for item in config["users"] if item.get("username") == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    was_admin = user.get("role") == "Admin"
    if username == request.state.analyst and payload.enabled is False:
        raise HTTPException(status_code=422, detail="You cannot disable your current account")
    if payload.display_name is not None:
        user["display_name"] = payload.display_name
    if payload.email is not None:
        user["email"] = _validated_email(payload.email)
    if payload.password:
        user["salt"], user["password_hash"] = _hash_password(payload.password)
    if payload.role:
        user["role"] = payload.role
    if payload.permissions is not None:
        user["permissions"] = sorted(set(payload.permissions) & set(ALL_FEATURES))
    if user["role"] in FULL_UI_ROLES:
        user["permissions"] = list(ALL_FEATURES)
    else:
        user["permissions"] = sorted(set(user.get("permissions") or EXPERT_FEATURES) & set(EXPERT_FEATURES))
    enabled_admins = [
        item for item in config["users"]
        if item.get("role") == "Admin" and item.get("enabled", True) and item is not user
    ]
    removes_last_admin = was_admin and (
        (payload.role is not None and payload.role != "Admin")
        or payload.enabled is False
    )
    if removes_last_admin and not enabled_admins:
        raise HTTPException(status_code=422, detail="At least one enabled administrator account is required")
    if payload.enabled is not None:
        user["enabled"] = payload.enabled
    write_config(config)
    return public_user(user)


@router.delete("/settings/users/{username}")
async def delete_user(username: str, request: Request):
    require_feature(request, "settings", admin_only=True)
    if username == request.state.analyst:
        raise HTTPException(status_code=422, detail="You cannot delete your current account")
    config = read_config()
    user = next((item for item in config["users"] if item.get("username") == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("role") == "Admin" and sum(item.get("role") == "Admin" and item.get("enabled", True) for item in config["users"]) <= 1:
        raise HTTPException(status_code=422, detail="At least one enabled administrator account is required")
    config["users"] = [item for item in config["users"] if item.get("username") != username]
    write_config(config)
    return {"deleted": True, "username": username}


@router.get("/settings/siem/schema")
async def siem_schema(request: Request):
    require_feature(request, "settings", sme_only=True)
    return {
        name: [{"name": field, "label": label, "type": kind, "required": required} for field, label, kind, required in fields]
        for name, fields in SIEM_SCHEMAS.items()
    }


@router.get("/settings/siem-status")
async def siem_status(request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    active = {item["id"] for item in telemetry_sources(config)["items"]}
    return [{
        "id": siem_type,
        "label": TELEMETRY_LABELS.get(siem_type, siem_type),
        "active": siem_type in active,
        "status": "connected" if siem_type in active else config.get("siem", {}).get(siem_type, {}).get("connection_status", "not tested"),
        "tested_at": config.get("siem", {}).get(siem_type, {}).get("connection_tested_at", ""),
    } for siem_type in ("folder", "wazuh", "logrhythm", "splunk", "qradar")]


@router.get("/settings/siem/{siem_type}")
async def get_siem(siem_type: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    if siem_type not in SIEM_SCHEMAS:
        raise HTTPException(status_code=404, detail="Unsupported SIEM")
    config = read_config()
    stored = config.get("siem", {}).get(siem_type, {}).get("settings", {})
    safe = {key: ("" if key in SECRET_FIELDS else value) for key, value in stored.items()}
    configured_secrets = [key for key in SECRET_FIELDS if stored.get(key)]
    return {
        "settings": safe,
        "configured_secrets": configured_secrets,
        "field_mapping": config.get("siem_field_mappings", {}).get(siem_type, {}),
        "field_inventory": config.get("siem_field_inventory", {}).get(siem_type, {}),
        "connection_status": "connected" if siem_type == "folder" else config.get("siem", {}).get(siem_type, {}).get("connection_status", "not tested"),
    }


@router.put("/settings/siem/{siem_type}")
async def save_siem(siem_type: str, payload: SiemSettings, request: Request):
    require_feature(request, "settings", sme_only=True)
    if siem_type not in SIEM_SCHEMAS:
        raise HTTPException(status_code=404, detail="Unsupported SIEM")
    allowed = {field[0] for field in SIEM_SCHEMAS[siem_type]}
    config = read_config()
    current = dict(config.get("siem", {}).get(siem_type, {}).get("settings", {}))
    for key, value in payload.settings.items():
        if key in allowed and (key not in SECRET_FIELDS or str(value)):
            current[key] = str(value)
    missing = [name for name, _label, _kind, required in SIEM_SCHEMAS[siem_type] if required and not current.get(name)]
    if missing:
        raise HTTPException(status_code=422, detail=f"Required settings missing: {', '.join(missing)}")
    prior = config.setdefault("siem", {}).get(siem_type, {})
    config["siem"][siem_type] = {
        "settings": current,
        "updated_at": datetime.now().astimezone().isoformat(),
        "connection_status": "connected" if siem_type == "folder" else "not tested",
        "connection_tested_at": prior.get("connection_tested_at", "") if siem_type == "folder" else "",
    }
    if payload.field_mapping:
        config.setdefault("siem_field_mappings", {})[siem_type] = {
            str(field).strip(): str(vendor_field).strip()
            for field, vendor_field in payload.field_mapping.items()
            if str(field).strip() and str(vendor_field).strip()
        }
    write_config(config)
    return await get_siem(siem_type, request)


@router.post("/settings/siem/{siem_type}/test")
async def test_siem(siem_type: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    try:
        result = await _upstream("POST", f"/siem/test/{siem_type}")
    except HTTPException:
        if siem_type != "folder":
            config.setdefault("siem", {}).setdefault(siem_type, {})["connection_status"] = "failed"
            config["siem"][siem_type]["connection_tested_at"] = datetime.now().astimezone().isoformat()
            write_config(config)
        raise
    entry = config.setdefault("siem", {}).setdefault(siem_type, {})
    entry["connection_status"] = "connected"
    entry["connection_tested_at"] = datetime.now().astimezone().isoformat()
    write_config(config)
    return {**result, "active": True, "tested_at": entry["connection_tested_at"]}


@router.post("/settings/siem/{siem_type}/fields-csv")
async def upload_siem_fields(siem_type: str, request: Request, file: UploadFile = File(...)):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    if not is_active_telemetry_source(siem_type, config):
        raise HTTPException(status_code=422, detail="Select an active, successfully tested telemetry source")
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="Upload a CSV file")
    content = await file.read(2_000_001)
    if len(content) > 2_000_000:
        raise HTTPException(status_code=413, detail="Field CSV must be 2 MB or smaller")
    try:
        rows = list(csv.reader(io.StringIO(content.decode("utf-8-sig"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise HTTPException(status_code=422, detail=f"Could not read CSV: {exc}") from exc
    if any(any(str(cell).strip() for cell in row[1:]) for row in rows):
        raise HTTPException(status_code=422, detail="CSV must contain exactly one populated column")
    values = [str(row[0]).strip() for row in rows if row and str(row[0]).strip()]
    if values and values[0].lower().replace(" ", "_") in {"field", "fields", "field_name", "available_fields", "column_name"}:
        values = values[1:]
    fields, seen = [], set()
    for value in values:
        marker = value.casefold()
        if marker not in seen:
            seen.add(marker)
            fields.append(value)
    if not fields:
        raise HTTPException(status_code=422, detail="CSV does not contain any field names")
    if len(fields) > 10_000:
        raise HTTPException(status_code=422, detail="CSV contains more than 10,000 fields")
    inventory = {
        "filename": Path(file.filename or "fields.csv").name,
        "fields": fields,
        "field_count": len(fields),
        "uploaded_at": datetime.now().astimezone().isoformat(),
    }
    config.setdefault("siem_field_inventory", {})[siem_type] = inventory
    write_config(config)
    return inventory


@router.delete("/settings/siem/{siem_type}/fields-csv")
async def delete_siem_fields(siem_type: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    removed = config.setdefault("siem_field_inventory", {}).pop(siem_type, None)
    write_config(config)
    return {"deleted": bool(removed), "siem_type": siem_type}


async def _discover_and_compile_siem(siem_type: str) -> dict:
    discovered = await _upstream(
        "POST",
        f"/siem/schema/{siem_type}/discover",
        params={"sample_limit": 50},
        timeout=httpx.Timeout(300, connect=10),
    )
    inventory = {
        "source": "automatic_discovery",
        "fields": [
            str(item.get("name"))
            for item in discovered.get("fields", [])
            if isinstance(item, dict) and item.get("name")
        ],
        # Persist names/types only. Sample values stay in the short-lived
        # Redis snapshot and never enter the runtime configuration file.
        "field_metadata": [
            {"name": str(item.get("name")), "type": str(item.get("type", "unknown"))}
            for item in discovered.get("fields", [])
            if isinstance(item, dict) and item.get("name")
        ],
        "field_count": int(discovered.get("field_count", 0)),
        "records_sampled": int(discovered.get("records_sampled", 0)),
        "last_verified": discovered.get("last_verified", ""),
        "schema_version": discovered.get("schema_version", ""),
        "drift": discovered.get("drift", {}),
    }
    config = read_config()
    config.setdefault("siem_field_inventory", {})[siem_type] = inventory
    write_config(config)
    compiled = await _upstream(
        "POST",
        f"/sigma/compile/{siem_type}",
        timeout=httpx.Timeout(1200, connect=10),
    )
    return {"siem_type": siem_type, "inventory": inventory, "compilation": compiled}


@router.post("/settings/siem/{siem_type}/discover")
async def discover_siem_fields_now(siem_type: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    if siem_type not in {"wazuh", "splunk", "qradar", "logrhythm"}:
        raise HTTPException(status_code=404, detail="Automatic discovery requires a live SIEM")
    if not is_active_telemetry_source(siem_type):
        raise HTTPException(status_code=422, detail="Test and activate the SIEM connection first")
    return await _discover_and_compile_siem(siem_type)


def _sigma_catalog() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for source, root in (("Community", SIGMAHQ_DIR), ("Local", SIGMA_LOCAL_DIR)):
        if not root.is_dir():
            continue
        for path in root.rglob("*.yml"):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if raw.get("id") and raw.get("title"):
                results.append({
                    "id": str(raw["id"]), "title": str(raw["title"]),
                    "level": str(raw.get("level", "medium")).lower(),
                    "severity": str(raw.get("level", "medium")).lower(),
                    "status": str(raw.get("status", "stable")), "source": source,
                    "tags": [str(tag) for tag in raw.get("tags", [])],
                })
    return results


@router.get("/settings/sigma")
async def sigma_rules(
    request: Request, query: str = "", page: int = 1, page_size: int = 50,
    sort_by: str = "severity",
):
    require_feature(request, "settings", sme_only=True)
    disabled = set(read_config()["sigma"].get("disabled_rule_ids", []))
    needle = query.strip().lower()
    rules = _sigma_catalog()
    if needle:
        rules = [rule for rule in rules if needle in f"{rule['id']} {rule['title']} {' '.join(rule['tags'])}".lower()]
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    if sort_by == "title":
        rules.sort(key=lambda item: (item["title"].casefold(), item["source"]))
    else:
        rules.sort(key=lambda item: (severity_rank.get(item["severity"], 5), item["title"].casefold()))
    page_size = max(10, min(page_size, 200))
    page = max(1, page)
    start = (page - 1) * page_size
    return {
        "items": [{**rule, "enabled": rule["id"] not in disabled} for rule in rules[start:start + page_size]],
        "total": len(rules), "page": page, "page_size": page_size,
        "schedules": read_config()["sigma"].get("schedules", []),
    }


@router.put("/settings/sigma/{rule_id}")
async def toggle_sigma(rule_id: str, payload: RuleToggle, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    disabled = set(config["sigma"].get("disabled_rule_ids", []))
    disabled.discard(rule_id) if payload.enabled else disabled.add(rule_id)
    config["sigma"]["disabled_rule_ids"] = sorted(disabled)
    write_config(config)
    return {"rule_id": rule_id, "enabled": payload.enabled}


def _schedule_collection(config: dict, kind: str) -> list[dict]:
    return config["hypothesis_schedules"] if kind == "hypothesis" else config["sigma"].setdefault("schedules", [])


_HYPOTHESIS_SEVERITY_BY_TACTIC = {
    "reconnaissance": "low",
    "resource development": "low",
    "discovery": "medium",
    "collection": "medium",
    "execution": "high",
    "persistence": "high",
    "privilege escalation": "high",
    "defense evasion": "high",
    "credential access": "critical",
    "lateral movement": "high",
    "command and control": "high",
    "exfiltration": "critical",
    "impact": "critical",
}


def hypothesis_severity(item: dict[str, Any]) -> str:
    """Return the canonical severity type used by every hypothesis view."""
    explicit = str(item.get("severity", "")).strip().lower()
    if explicit in {"low", "medium", "high", "critical"}:
        return explicit
    return _HYPOTHESIS_SEVERITY_BY_TACTIC.get(
        str(item.get("tactic", "")).strip().lower(),
        "medium",
    )


async def _hypothesis_schedule_targets(target_ids: list[str], severity: str | None) -> list[dict[str, Any]]:
    upstream = await _upstream("GET", "/hypotheses")
    config = read_config()
    catalog = [
        *(upstream if isinstance(upstream, list) else []),
        *config.get("custom_hypotheses", []),
    ]
    by_id = {str(item.get("id", "")): item for item in catalog if item.get("id")}
    missing = [target_id for target_id in target_ids if target_id not in by_id]
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown hypothesis: {missing[0]}")
    targets: list[dict[str, Any]] = []
    for target_id in dict.fromkeys(target_ids):
        source = by_id[target_id]
        normalized_severity = hypothesis_severity(source)
        if severity and severity != "all" and normalized_severity != severity:
            raise HTTPException(
                status_code=422,
                detail=f"{target_id} is {normalized_severity} severity, not {severity}",
            )
        targets.append({
            "id": target_id,
            "title": str(source.get("title") or source.get("text") or target_id)[:500],
            "severity": normalized_severity,
            "hypothesis_text": source.get("text", "") if source.get("custom") else "",
            "hypothesis_tactic": source.get("tactic", "") if source.get("custom") else "",
            "hypothesis_technique": source.get("technique", "") if source.get("custom") else "",
        })
    return targets


@router.get("/settings/schedules/{kind}")
async def list_schedules(kind: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    if kind not in {"hypothesis", "sigma"}:
        raise HTTPException(status_code=404, detail="Unknown schedule type")
    return _schedule_collection(read_config(), kind)


@router.post("/settings/schedules/{kind}", status_code=201)
async def create_schedule(kind: str, payload: ScheduleRequest, request: Request):
    require_feature(request, "settings", sme_only=True)
    if kind not in {"hypothesis", "sigma"}:
        raise HTTPException(status_code=404, detail="Unknown schedule type")
    if not is_active_telemetry_source(payload.siem_type):
        raise HTTPException(status_code=422, detail="Schedules require an active, successfully tested telemetry source")
    if any(day < 0 or day > 6 for day in payload.days):
        raise HTTPException(status_code=422, detail="days must use 0=Monday through 6=Sunday")
    if payload.frequency in {"hourly", "daily"} and payload.interval > 24:
        unit = "hours" if payload.frequency == "hourly" else "runs per day"
        raise HTTPException(status_code=422, detail=f"{unit} must be between 1 and 24")
    config = read_config()
    item = {"id": uuid.uuid4().hex[:12], "kind": kind, **payload.model_dump(), "last_run_key": "", "last_status": "never"}
    if kind == "hypothesis":
        target_ids = payload.target_ids or [payload.target_id]
        targets = await _hypothesis_schedule_targets(target_ids, payload.severity)
        selected_severity = payload.severity or targets[0]["severity"]
        if selected_severity != "all" and any(target["severity"] != selected_severity for target in targets):
            raise HTTPException(
                status_code=422,
                detail="All hypotheses in one schedule must use the same severity type",
            )
        item.update({
            "target_id": targets[0]["id"],
            "target_ids": [target["id"] for target in targets],
            "hypothesis_targets": targets,
            "target_count": len(targets),
            "schedule_scope": "severity" if payload.schedule_scope == "severity" or len(targets) > 1 else "individual",
            "severity": selected_severity,
            "title": (
                (
                    f"All severity groups ({len(targets)} hypotheses)"
                    if selected_severity == "all"
                    else f"{selected_severity.title()} severity group ({len(targets)} hypotheses)"
                )
                if payload.schedule_scope == "severity" or len(targets) > 1
                else (payload.title or targets[0]["title"])
            ),
        })
    else:
        rule = next((candidate for candidate in _sigma_catalog() if candidate.get("id") == payload.target_id), None)
        item["severity"] = (rule or {}).get("severity", "medium")
    _schedule_collection(config, kind).append(item)
    write_config(config)
    return item


@router.delete("/settings/schedules/{kind}/{schedule_id}")
async def delete_schedule(kind: str, schedule_id: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    if kind not in {"hypothesis", "sigma"}:
        raise HTTPException(status_code=404, detail="Unknown schedule type")
    config = read_config()
    collection = _schedule_collection(config, kind)
    before = len(collection)
    collection[:] = [item for item in collection if item.get("id") != schedule_id]
    write_config(config)
    return {"deleted": len(collection) < before}


async def _refresh_ioc_source(source_id: str) -> dict:
    from services.enrichment.ioc_management import refresh_source

    config = read_config()
    source = next((item for item in config.get("ioc_sources", []) if item.get("id") == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="IOC source not found")
    try:
        result = await refresh_source(dict(source))
        status, error = "completed", ""
    except Exception as exc:  # noqa: BLE001 - persist fetch outcome for operators
        result, status, error = {}, "failed", str(exc)
    config = read_config()
    stored = next((item for item in config.get("ioc_sources", []) if item.get("id") == source_id), None)
    if stored:
        stored.update({
            "last_status": status,
            "last_error": error[:4000],
            "last_run_at": datetime.now().astimezone().isoformat(),
            "last_result": result,
        })
        write_config(config)
    if error:
        raise HTTPException(status_code=422, detail=error)
    return result


async def _run_scheduled_ioc_refresh(source_id: str) -> None:
    try:
        await _refresh_ioc_source(source_id)
    except HTTPException:
        logger.exception("scheduled IOC source refresh failed for %s", source_id)


@router.get("/settings/ioc-sources")
async def list_ioc_sources(request: Request):
    require_feature(request, "settings", sme_only=True)
    return read_config().get("ioc_sources", [])


@router.post("/settings/ioc-sources", status_code=201)
async def create_ioc_source(payload: IOCSourceCreate, request: Request):
    require_feature(request, "settings", sme_only=True)
    if any(day < 0 or day > 6 for day in payload.days):
        raise HTTPException(status_code=422, detail="days must use 0=Monday through 6=Sunday")
    if payload.frequency in {"hourly", "daily"} and payload.interval > 24:
        raise HTTPException(status_code=422, detail="hourly/daily interval must be between 1 and 24")
    config = read_config()
    item = {
        "id": uuid.uuid4().hex[:12],
        **payload.model_dump(),
        "created_by": request.state.analyst,
        "created_at": datetime.now().astimezone().isoformat(),
        "last_run_key": "",
        "last_status": "never",
        "last_error": "",
    }
    config.setdefault("ioc_sources", []).append(item)
    write_config(config)
    return item


@router.post("/settings/ioc-sources/upload", status_code=201)
async def upload_ioc_source(
    request: Request,
    file: UploadFile = File(...),
    name: str = Form(...),
    confidence: str = Form("medium"),
):
    require_feature(request, "settings", sme_only=True)
    from services.enrichment.ioc_management import LOCAL_SOURCE_ROOT, MAX_SOURCE_BYTES

    if confidence not in {"low", "medium", "high"}:
        raise HTTPException(status_code=422, detail="invalid confidence")
    content = await file.read(MAX_SOURCE_BYTES + 1)
    await file.close()
    if not content or len(content) > MAX_SOURCE_BYTES:
        raise HTTPException(status_code=413, detail="IOC source file is empty or exceeds the configured limit")
    LOCAL_SOURCE_ROOT.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(file.filename or "source.dat").name)[:160]
    path = (LOCAL_SOURCE_ROOT / f"{uuid.uuid4().hex}_{safe}").resolve()
    if path.parent != LOCAL_SOURCE_ROOT.resolve():
        raise HTTPException(status_code=422, detail="invalid IOC source filename")
    path.write_bytes(content)
    payload = IOCSourceCreate(
        name=name.strip(), kind="local", location=str(path), confidence=confidence,
        enabled=False,
    )
    return await create_ioc_source(payload, request)


@router.put("/settings/ioc-sources/{source_id}")
async def update_ioc_source(source_id: str, payload: IOCSourceCreate, request: Request):
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    source = next((item for item in config.get("ioc_sources", []) if item.get("id") == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="IOC source not found")
    source.update(payload.model_dump())
    write_config(config)
    return source


@router.delete("/settings/ioc-sources/{source_id}")
async def delete_ioc_source(source_id: str, request: Request):
    require_feature(request, "settings", admin_only=True)
    config = read_config()
    before = len(config.get("ioc_sources", []))
    config["ioc_sources"] = [
        item for item in config.get("ioc_sources", []) if item.get("id") != source_id
    ]
    if len(config["ioc_sources"]) == before:
        raise HTTPException(status_code=404, detail="IOC source not found")
    write_config(config)
    return {"deleted": True, "source_id": source_id}


@router.post("/settings/ioc-sources/{source_id}/refresh")
async def refresh_ioc_source_now(source_id: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    return await _refresh_ioc_source(source_id)


@router.post("/settings/ioc-sources/refresh-all")
async def refresh_all_ioc_sources(request: Request):
    require_feature(request, "settings", sme_only=True)
    results = []
    for source in read_config().get("ioc_sources", []):
        try:
            results.append(await _refresh_ioc_source(str(source["id"])))
        except HTTPException as exc:
            results.append({"source_id": source.get("id"), "error": exc.detail})
    return {"results": results}


@router.get("/detections")
async def scheduled_detections(request: Request, limit: int = 100):
    require_feature(request, "reports")
    return await _upstream("GET", "/sigma/detections", params={"limit": max(1, min(limit, 500))})


@router.get("/knowledge/documents")
async def kb_documents(request: Request):
    require_feature(request, "knowledge")
    return await _upstream("GET", "/kb/documents")


@router.post("/knowledge/upload")
async def kb_upload(request: Request, file: UploadFile = File(...)):
    require_feature(request, "knowledge")
    content = await file.read()
    files = {"file": (file.filename or "document.txt", content, file.content_type or "application/octet-stream")}
    return await _upstream("POST", "/kb/upload", files=files, timeout=httpx.Timeout(180, connect=10))


@router.delete("/knowledge/documents/{doc_id}")
async def kb_delete(doc_id: str, request: Request):
    require_feature(request, "knowledge")
    return await _upstream("DELETE", f"/kb/documents/{doc_id}")


@router.post("/chat")
async def model_chat(payload: ChatRequest, request: Request):
    require_feature(request, "chat")
    return await _upstream("POST", "/chat", json={**payload.model_dump(), "analyst": request.state.analyst}, timeout=httpx.Timeout(300, connect=10))


@router.get("/chat/conversations")
async def chat_conversations(request: Request):
    require_feature(request, "chat")
    return await _upstream("GET", "/chat/conversations", params={"analyst": request.state.analyst})


@router.post("/chat/conversations", status_code=201)
async def create_chat_conversation(payload: ChatConversationCreate, request: Request):
    require_feature(request, "chat")
    return await _upstream(
        "POST", "/chat/conversations",
        json={"analyst": request.state.analyst, "title": payload.title},
    )


@router.get("/chat/conversations/{conversation_id}")
async def get_chat_conversation(conversation_id: str, request: Request):
    require_feature(request, "chat")
    return await _upstream(
        "GET", f"/chat/conversations/{conversation_id}",
        params={"analyst": request.state.analyst},
    )


@router.delete("/chat/conversations/{conversation_id}")
async def delete_chat_conversation(conversation_id: str, request: Request):
    require_feature(request, "chat")
    return await _upstream(
        "DELETE", f"/chat/conversations/{conversation_id}",
        params={"analyst": request.state.analyst},
    )


async def _execute_schedule(item: dict[str, Any]) -> None:
    kind = item.get("kind", "hypothesis")
    base_payload: dict[str, Any] = {}
    if kind == "hypothesis":
        base_payload = {
            "hunter_name": "scheduler",
            "siem_type": item.get("siem_type", "mock"),
            "log_source_path": item.get("log_source_path"),
            "max_iterations": int(read_config()["general"].get("default_iterations", 1)),
            "cover_style": "2",
        }
    else:
        siem_type = item.get("siem_type", "mock")
        payload = {
            "schedule_id": item["id"],
            "rule_id": item["target_id"],
            "siem_type": siem_type,
            "log_source_path": item.get("log_source_path") or (os.environ.get("LOG_SOURCE_DIR", "/data/log_sources") if siem_type == "folder" else None),
        }
    status, error = "completed", ""
    result_summary: dict[str, Any] = {}
    try:
        if kind == "sigma":
            result = await _upstream("POST", "/sigma/scheduled/run", json=payload, timeout=httpx.Timeout(1200, connect=10))
            status = str(result.get("status", "completed"))
        else:
            targets = item.get("hypothesis_targets") or [{
                "id": item["target_id"],
                "hypothesis_text": item.get("hypothesis_text"),
                "hypothesis_tactic": item.get("hypothesis_tactic", ""),
                "hypothesis_technique": item.get("hypothesis_technique", ""),
            }]
            completed, failures = 0, []
            for target in targets:
                payload = {
                    **base_payload,
                    "hypothesis_id": target["id"],
                    "hypothesis_text": target.get("hypothesis_text") or None,
                    "hypothesis_tactic": target.get("hypothesis_tactic", ""),
                    "hypothesis_technique": target.get("hypothesis_technique", ""),
                }
                try:
                    result = await _upstream("POST", "/hunt", json=payload, timeout=httpx.Timeout(1200, connect=10))
                    if result.get("error"):
                        failures.append({"hypothesis_id": target["id"], "error": str(result["error"])})
                    else:
                        completed += 1
                except Exception as exc:  # noqa: BLE001 - continue the selected severity group
                    failures.append({"hypothesis_id": target["id"], "error": str(exc)})
                    logger.exception("scheduled hypothesis failed for %s", target["id"])
            status = "completed" if not failures else ("partial" if completed else "failed")
            error = "; ".join(f"{failure['hypothesis_id']}: {failure['error']}" for failure in failures)[:4000]
            result_summary = {
                "selected": len(targets),
                "completed": completed,
                "failed": len(failures),
                "failures": failures[:20],
            }
    except Exception as exc:  # noqa: BLE001
        status, error = "failed", str(exc)
        logger.exception("scheduled %s run failed", item.get("kind"))
    config = read_config()
    collection = _schedule_collection(config, kind)
    for stored in collection:
        if stored.get("id") == item.get("id"):
            stored.update({
                "last_status": status,
                "last_error": error,
                "last_result": result_summary,
                "last_run_at": datetime.now().astimezone().isoformat(),
            })
    write_config(config)


def _schedule_is_due(item: dict[str, Any], now: datetime) -> bool:
    """Evaluate minute/hour/day schedules in system-local wall-clock time.

    ``time`` is the anchor. Daily schedules distribute N runs evenly over the
    24-hour day starting at that anchor (for example, twice daily at 02:00
    runs at 02:00 and 14:00). Legacy schedules without frequency fields retain
    their original once-daily behavior.
    """
    if now.weekday() not in item.get("days", list(range(7))):
        return False
    try:
        anchor_hour, anchor_minute = map(int, str(item.get("time", "00:00")).split(":"))
        interval = int(item.get("interval", 1))
    except (TypeError, ValueError):
        return False
    frequency = str(item.get("frequency", "daily"))
    minute_of_day = now.hour * 60 + now.minute
    anchor = anchor_hour * 60 + anchor_minute

    if frequency == "minutes" and 1 <= interval <= 59:
        absolute_minute = now.toordinal() * 1440 + minute_of_day
        absolute_anchor = anchor
        return (absolute_minute - absolute_anchor) % interval == 0
    if frequency == "hourly" and 1 <= interval <= 24:
        if now.minute != anchor_minute:
            return False
        absolute_hour = now.toordinal() * 24 + now.hour
        return (absolute_hour - anchor_hour) % interval == 0
    if frequency == "daily" and 1 <= interval <= 24:
        slots = {round(anchor + index * 1440 / interval) % 1440 for index in range(interval)}
        return minute_of_day in slots
    return False


def _parse_local_datetime(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    except (TypeError, ValueError):
        return None


def _schema_refresh_is_due(config: dict[str, Any], now: datetime) -> bool:
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.now().astimezone().tzinfo)
    maintenance = config.get("maintenance", {})
    if not maintenance.get("schema_refresh_enabled", True):
        return False
    live = [item for item in telemetry_sources(config)["items"] if item["id"] != "folder"]
    if not live:
        return False
    last_started = _parse_local_datetime(maintenance.get("schema_refresh_last_started_at"))
    last_completed = _parse_local_datetime(maintenance.get("schema_refresh_last_completed_at"))
    status = str(maintenance.get("schema_refresh_last_status", "never"))
    if status == "running" and last_started and now - last_started < timedelta(hours=6):
        return False
    if status in {"failed", "partial"}:
        retry_hours = max(1, int(os.environ.get(
            "SIEM_SCHEMA_REFRESH_RETRY_HOURS",
            str(maintenance.get("schema_refresh_retry_hours", 6)),
        )))
        reference = last_started or last_completed
        return reference is None or now - reference >= timedelta(hours=retry_hours)
    interval = max(24, int(os.environ.get(
        "SIEM_SCHEMA_REFRESH_INTERVAL_HOURS",
        str(maintenance.get("schema_refresh_interval_hours", 168)),
    )))
    reference = last_completed or last_started
    return reference is None or now - reference >= timedelta(hours=interval)


async def _run_schema_refresh() -> None:
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    config = read_config()
    sources = [item["id"] for item in telemetry_sources(config)["items"] if item["id"] != "folder"]
    for siem_type in sources:
        try:
            results.append(await _discover_and_compile_siem(siem_type))
        except Exception as exc:  # noqa: BLE001 - isolate each SIEM maintenance pass
            errors.append(f"{siem_type}: {exc}")
            logger.exception("weekly schema/compile maintenance failed for %s", siem_type)
    config = read_config()
    maintenance = config.setdefault("maintenance", {})
    maintenance.update({
        "schema_refresh_last_completed_at": datetime.now().astimezone().isoformat(),
        "schema_refresh_last_status": "completed" if not errors else ("partial" if results else "failed"),
        "schema_refresh_last_error": "; ".join(errors)[:4000],
        "schema_refresh_last_results": [
            {
                "siem_type": item["siem_type"],
                "field_count": item["inventory"].get("field_count", 0),
                "schema_version": item["inventory"].get("schema_version", ""),
                "ready_rules": item["compilation"].get("ready", 0),
                "uncompilable_rules": item["compilation"].get("uncompilable", 0),
                "compilation_status": item["compilation"].get("status", "unknown"),
            }
            for item in results
        ],
    })
    write_config(config)


async def _scheduler_loop() -> None:
    global _schema_refresh_task
    while True:
        try:
            now = datetime.now().astimezone()
            run_key = now.strftime("%Y-%m-%d %H:%M")
            config = read_config()
            due: list[dict[str, Any]] = []
            maintenance_due = (
                (_schema_refresh_task is None or _schema_refresh_task.done())
                and _schema_refresh_is_due(config, now)
            )
            for kind in ("hypothesis", "sigma"):
                for item in _schedule_collection(config, kind):
                    if not item.get("enabled", True) or not _schedule_is_due(item, now):
                        continue
                    if item.get("last_run_key") == run_key:
                        continue
                    item["last_run_key"] = run_key
                    item["last_status"] = "running"
                    due.append(dict(item))
            due_ioc_sources: list[str] = []
            for source in config.get("ioc_sources", []):
                if not source.get("enabled", True) or not _schedule_is_due(source, now):
                    continue
                if source.get("last_run_key") == run_key:
                    continue
                source["last_run_key"] = run_key
                source["last_status"] = "running"
                due_ioc_sources.append(str(source.get("id", "")))
            if maintenance_due:
                config.setdefault("maintenance", {}).update({
                    "schema_refresh_last_started_at": now.isoformat(),
                    "schema_refresh_last_status": "running",
                    "schema_refresh_last_error": "",
                })
            if due or due_ioc_sources or maintenance_due:
                write_config(config)
                for item in due:
                    asyncio.create_task(_execute_schedule(item))
                for source_id in due_ioc_sources:
                    if source_id:
                        asyncio.create_task(
                            _run_scheduled_ioc_refresh(source_id),
                            name=f"ioc-source-refresh-{source_id}",
                        )
                if maintenance_due:
                    _schema_refresh_task = asyncio.create_task(
                        _run_schema_refresh(),
                        name="weekly-siem-schema-refresh",
                    )
        except Exception:  # noqa: BLE001
            logger.exception("settings scheduler tick failed")
        await asyncio.sleep(20)


def start_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = asyncio.create_task(_scheduler_loop())


async def stop_scheduler() -> None:
    global _scheduler_task, _schema_refresh_task
    if _scheduler_task:
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
        _scheduler_task = None
    if _schema_refresh_task:
        _schema_refresh_task.cancel()
        try:
            await _schema_refresh_task
        except asyncio.CancelledError:
            pass
        _schema_refresh_task = None
