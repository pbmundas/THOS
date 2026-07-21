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
import secrets
import time as time_module
from datetime import datetime
from typing import Any
import uuid

import httpx
import yaml
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
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
ALL_FEATURES = ("hunts", "reports", "chat", "knowledge", "settings")
_scheduler_task: asyncio.Task | None = None
if hasattr(time_module, "tzset"):
    time_module.tzset()


def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex(), digest.hex()


def seed_users(accounts: list[tuple[str, str]]) -> None:
    config = read_config()
    if config.get("users"):
        return
    users = []
    for index, (username, password) in enumerate(accounts):
        salt, password_hash = _hash_password(password)
        role = "SME" if index == 0 else "Analyst"
        users.append({
            "username": username,
            "display_name": username,
            "role": role,
            "permissions": list(ALL_FEATURES if role == "SME" else ("hunts", "reports")),
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
        "role": user.get("role", "Analyst"),
        "permissions": user.get("permissions", []),
        "enabled": bool(user.get("enabled", True)),
        "created_at": user.get("created_at", ""),
    }


def require_feature(request: Request, feature: str, *, sme_only: bool = False) -> None:
    if sme_only and request.state.role != "SME":
        raise HTTPException(status_code=403, detail="SME administrator access is required")
    if feature not in request.state.permissions:
        raise HTTPException(status_code=403, detail=f"Your role does not permit {feature}")


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
    role: str = Field(pattern="^(SME|Analyst)$")
    permissions: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    password: str | None = Field(default=None, min_length=10, max_length=512)
    role: str | None = Field(default=None, pattern="^(SME|Analyst)$")
    permissions: list[str] | None = None
    enabled: bool | None = None


class SiemSettings(BaseModel):
    settings: dict[str, str | int | bool] = Field(default_factory=dict)
    field_mapping: dict[str, str] = Field(default_factory=dict)


class RuleToggle(BaseModel):
    enabled: bool


class ScheduleRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=256)
    title: str = Field(default="", max_length=500)
    time: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    days: list[int] = Field(default_factory=lambda: list(range(7)))
    enabled: bool = True
    siem_type: str = Field(default="mock", pattern="^(mock|folder|wazuh|logrhythm|splunk|qradar)$")
    log_source_path: str | None = None


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=16_000)
    history: list[dict[str, str]] = Field(default_factory=list)


class HypothesisCreate(BaseModel):
    title: str = Field(min_length=8, max_length=300)
    text: str = Field(min_length=20, max_length=16_000)
    tactic: str = Field(min_length=2, max_length=120)
    technique: str = Field(default="", max_length=32, pattern=r"^(?:T\d{4}(?:\.\d{3})?)?$")


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
    items = [{"id": "folder", "label": TELEMETRY_LABELS["folder"], "tested_at": "built-in"}]
    for siem_type in ("wazuh", "logrhythm", "splunk", "qradar"):
        entry = config.get("siem", {}).get(siem_type, {})
        if entry.get("connection_status") == "connected":
            items.append({
                "id": siem_type,
                "label": TELEMETRY_LABELS[siem_type],
                "tested_at": entry.get("connection_tested_at", ""),
            })
    active_ids = {item["id"] for item in items}
    preferred = str(config.get("general", {}).get("default_siem", "folder"))
    return {"items": items, "default": preferred if preferred in active_ids else "folder"}


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
    require_feature(request, "settings", sme_only=True)
    return [public_user(user) for user in read_config().get("users", [])]


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
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    if any(user.get("username", "").lower() == payload.username.lower() for user in config["users"]):
        raise HTTPException(status_code=409, detail="Username already exists")
    permissions = list(ALL_FEATURES) if payload.role == "SME" else sorted(set(payload.permissions) & set(ALL_FEATURES))
    salt, password_hash = _hash_password(payload.password)
    user = {
        "username": payload.username,
        "display_name": payload.display_name,
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
    require_feature(request, "settings", sme_only=True)
    config = read_config()
    user = next((item for item in config["users"] if item.get("username") == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if username == request.state.analyst and payload.enabled is False:
        raise HTTPException(status_code=422, detail="You cannot disable your current account")
    if payload.display_name is not None:
        user["display_name"] = payload.display_name
    if payload.password:
        user["salt"], user["password_hash"] = _hash_password(payload.password)
    if payload.role:
        user["role"] = payload.role
    if payload.permissions is not None:
        user["permissions"] = sorted(set(payload.permissions) & set(ALL_FEATURES))
    if user["role"] == "SME":
        user["permissions"] = list(ALL_FEATURES)
    if payload.enabled is not None:
        user["enabled"] = payload.enabled
    write_config(config)
    return public_user(user)


@router.delete("/settings/users/{username}")
async def delete_user(username: str, request: Request):
    require_feature(request, "settings", sme_only=True)
    if username == request.state.analyst:
        raise HTTPException(status_code=422, detail="You cannot delete your current account")
    config = read_config()
    user = next((item for item in config["users"] if item.get("username") == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("role") == "SME" and sum(item.get("role") == "SME" and item.get("enabled", True) for item in config["users"]) <= 1:
        raise HTTPException(status_code=422, detail="At least one enabled SME account is required")
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


def _sigma_catalog() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for source, root in (("SigmaHQ", SIGMAHQ_DIR), ("THOS", SIGMA_LOCAL_DIR)):
        if not root.is_dir():
            continue
        for path in root.rglob("*.yml"):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if raw.get("id") and raw.get("title"):
                results.append({
                    "id": str(raw["id"]), "title": str(raw["title"]), "level": str(raw.get("level", "medium")),
                    "status": str(raw.get("status", "stable")), "source": source,
                    "tags": [str(tag) for tag in raw.get("tags", [])],
                })
    return results


@router.get("/settings/sigma")
async def sigma_rules(request: Request, query: str = "", page: int = 1, page_size: int = 50):
    require_feature(request, "settings", sme_only=True)
    disabled = set(read_config()["sigma"].get("disabled_rule_ids", []))
    needle = query.strip().lower()
    rules = _sigma_catalog()
    if needle:
        rules = [rule for rule in rules if needle in f"{rule['id']} {rule['title']} {' '.join(rule['tags'])}".lower()]
    rules.sort(key=lambda item: (item["source"], item["title"]))
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
    config = read_config()
    item = {"id": uuid.uuid4().hex[:12], "kind": kind, **payload.model_dump(), "last_run_key": "", "last_status": "never"}
    if kind == "hypothesis":
        custom = next((candidate for candidate in config.get("custom_hypotheses", []) if candidate.get("id") == payload.target_id), None)
        if custom:
            item.update({
                "hypothesis_text": custom.get("text", ""),
                "hypothesis_tactic": custom.get("tactic", ""),
                "hypothesis_technique": custom.get("technique", ""),
            })
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


async def _execute_schedule(item: dict[str, Any]) -> None:
    payload: dict[str, Any] = {
        "hunter_name": "scheduler",
        "siem_type": item.get("siem_type", "mock"),
        "log_source_path": item.get("log_source_path"),
        "max_iterations": int(read_config()["general"].get("default_iterations", 1)),
        "cover_style": "2",
    }
    if item.get("kind") == "hypothesis":
        payload["hypothesis_id"] = item["target_id"]
        payload["hypothesis_text"] = item.get("hypothesis_text")
        payload["hypothesis_tactic"] = item.get("hypothesis_tactic", "")
        payload["hypothesis_technique"] = item.get("hypothesis_technique", "")
    else:
        payload["hypothesis_text"] = f"Scheduled Sigma validation for rule {item['target_id']}: {item.get('title', '')}"
    status, error = "completed", ""
    try:
        await _upstream("POST", "/hunt", json=payload, timeout=httpx.Timeout(1200, connect=10))
    except Exception as exc:  # noqa: BLE001
        status, error = "failed", str(exc)
        logger.exception("scheduled %s run failed", item.get("kind"))
    config = read_config()
    collection = _schedule_collection(config, item.get("kind", "hypothesis"))
    for stored in collection:
        if stored.get("id") == item.get("id"):
            stored.update({"last_status": status, "last_error": error, "last_run_at": datetime.now().astimezone().isoformat()})
    write_config(config)


async def _scheduler_loop() -> None:
    while True:
        try:
            now = datetime.now().astimezone()
            run_key = now.strftime("%Y-%m-%d %H:%M")
            config = read_config()
            due: list[dict[str, Any]] = []
            for kind in ("hypothesis", "sigma"):
                for item in _schedule_collection(config, kind):
                    if not item.get("enabled", True) or item.get("time") != now.strftime("%H:%M"):
                        continue
                    if now.weekday() not in item.get("days", list(range(7))) or item.get("last_run_key") == run_key:
                        continue
                    item["last_run_key"] = run_key
                    item["last_status"] = "running"
                    due.append(dict(item))
            if due:
                write_config(config)
                for item in due:
                    asyncio.create_task(_execute_schedule(item))
        except Exception:  # noqa: BLE001
            logger.exception("settings scheduler tick failed")
        await asyncio.sleep(20)


def start_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = asyncio.create_task(_scheduler_loop())


async def stop_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task:
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
        _scheduler_task = None
