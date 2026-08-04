"""Governed, non-executing forensic tool adapters.

The adapters in this module never invoke an evidence file as a program.  They
only pass a validated evidence path to an allowlisted static-analysis command
or parser.  Every invocation is time-bounded and output-bounded so a damaged or
hostile artifact cannot indefinitely occupy the forensic worker.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from services.runtime_config import get_value
from services.capacity import internal_worker_limit


TOOL_TIMEOUT_SECONDS = max(
    5,
    min(
        int(
            os.environ.get(
                "FORENSIC_TOOL_TIMEOUT_SECONDS",
                str(get_value("forensics", "tool_timeout_seconds", default=180)),
            )
        ),
        3600,
    ),
)
TOOL_OUTPUT_BYTES = max(
    4096,
    min(
        int(
            os.environ.get(
                "FORENSIC_TOOL_OUTPUT_BYTES",
                str(get_value("forensics", "tool_output_bytes", default=200000)),
            )
        ),
        5_000_000,
    ),
)
MAX_STATIC_FILE_BYTES = max(
    1,
    int(
        os.environ.get(
            "FORENSIC_MAX_STATIC_FILE_BYTES",
            str(
                get_value(
                    "forensics", "max_static_file_bytes", default=2 * 1024**3
                )
            ),
        )
    ),
)
STRINGS_MIN_LENGTH = max(
    4,
    min(
        int(
            os.environ.get(
                "FORENSIC_STRINGS_MIN_LENGTH",
                str(get_value("forensics", "strings_min_length", default=6)),
            )
        ),
        64,
    ),
)
CAPA_RULES_DIR = os.environ.get(
    "FORENSIC_CAPA_RULES_DIR",
    str(get_value("forensics", "capa_rules_dir", default="") or ""),
).strip()


def _load_tool_catalog() -> tuple[dict[str, Any], ...]:
    path = Path(__file__).with_name("data") / "tool_catalog.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    tools = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(tools, list) or not tools:
        raise RuntimeError("forensic tool capability catalog is missing or empty")
    normalized = []
    seen = set()
    for item in tools:
        if not isinstance(item, dict):
            raise RuntimeError("forensic tool catalog contains a non-object entry")
        tool_id = str(item.get("tool_id") or "").strip()
        if not tool_id or tool_id in seen:
            raise RuntimeError("forensic tool catalog contains a missing/duplicate tool_id")
        seen.add(tool_id)
        normalized.append(dict(item))
    return tuple(normalized)


# The shipped JSON capability catalog is the product source of truth. Keeping
# tool metadata outside executable code lets administrators extend or replace
# capabilities without embedding investigative choices in the adapters.
_TOOL_CATALOG = _load_tool_catalog()
_EXCLUDED_DEPLOYMENT_STATES = {
    "deprecated",
    "license_required",
    "not_installed",
    "unsupported",
    "unsupported_platform",
}


def _available(selector: str) -> bool:
    kind, _, value = selector.partition(":")
    if kind == "command":
        return bool(shutil.which(value))
    if kind == "python":
        return importlib.util.find_spec(value) is not None
    return False


def tool_status() -> dict:
    """Return only tools that are installed in this forensic worker."""
    items = []
    for spec in _TOOL_CATALOG:
        deployment = str(spec.get("deployment") or "").strip().lower()
        declared_status = str(spec.get("status") or "").strip().lower()
        if (
            deployment in _EXCLUDED_DEPLOYMENT_STATES
            or declared_status in _EXCLUDED_DEPLOYMENT_STATES
            or str(spec.get("execution") or "").strip().lower() == "status_only"
        ):
            continue
        installed = _available(str(spec["availability"]))
        if not installed:
            continue
        state = "available"
        detail: dict[str, Any] = {}
        if spec["tool_id"] == "clamav" and installed:
            database = Path("/var/lib/clamav")
            ready = (
                database.is_dir()
                and (any(database.glob("*.cvd")) or any(database.glob("*.cld")))
            )
            detail["signature_database_ready"] = ready
            if not ready:
                state = "degraded"
        if spec["tool_id"] == "capa" and installed:
            rules_ready = bool(CAPA_RULES_DIR and Path(CAPA_RULES_DIR).is_dir())
            detail["rules_ready"] = rules_ready
            if not rules_ready:
                state = "degraded"
        if state != "available":
            continue
        items.append({
            key: value for key, value in spec.items() if key != "availability"
        } | {
            "available": installed,
            "status": state,
            "execution": "agent_selected",
            **detail,
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "executes_samples": bool(
                get_value("forensics", "dynamic_analysis_enabled", default=False)
                and get_value("forensics", "cape", "enabled", default=False)
            ),
            "shell_commands": False,
            "timeout_seconds": TOOL_TIMEOUT_SECONDS,
            "output_byte_limit": TOOL_OUTPUT_BYTES,
            "max_static_file_bytes": MAX_STATIC_FILE_BYTES,
        },
        "tools": items,
    }


def _result(
    tool_id: str,
    status: str,
    *,
    applicable: bool = True,
    started_at: str | None = None,
    duration_ms: int = 0,
    exit_code: int | None = None,
    output: str = "",
    error: str = "",
    truncated: bool = False,
    data: Any = None,
    note: str = "",
) -> dict:
    return {
        "tool_id": tool_id,
        "status": status,
        "applicable": applicable,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "output": output,
        "error": error,
        "truncated": truncated,
        "data": data,
        "note": note,
    }


def _run(tool_id: str, command: list[str], timeout: int | None = None) -> dict:
    """Run one fixed argv command without a shell and cap captured output."""
    executable = shutil.which(command[0])
    if not executable:
        return _result(tool_id, "not_installed")
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout or TOOL_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
        raw = completed.stdout or b""
        output = raw[:TOOL_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return _result(
            tool_id,
            "completed" if completed.returncode in {0, 1} else "failed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            exit_code=completed.returncode,
            output=output,
            truncated=len(raw) > TOOL_OUTPUT_BYTES,
        )
    except subprocess.TimeoutExpired as exc:
        raw = bytes(exc.stdout or b"")
        return _result(
            tool_id,
            "timed_out",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            output=raw[:TOOL_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            truncated=len(raw) > TOOL_OUTPUT_BYTES,
            error=f"tool exceeded the {timeout or TOOL_TIMEOUT_SECONDS}s limit",
        )
    except OSError as exc:
        return _result(
            tool_id,
            "failed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=str(exc),
        )


def _pe_triage(path: Path) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    try:
        import pefile
    except ImportError:
        return _result("pefile", "not_installed")
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
        sections = [{
            "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "virtual_address": int(section.VirtualAddress),
            "virtual_size": int(section.Misc_VirtualSize),
            "raw_size": int(section.SizeOfRawData),
            "entropy": round(float(section.get_entropy()), 3),
        } for section in pe.sections[:96]]
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:256]:
            imports.append({
                "dll": (entry.dll or b"").decode("ascii", errors="replace"),
                "symbols": [
                    (item.name or f"ordinal:{item.ordinal}").decode(
                        "ascii", errors="replace"
                    ) if isinstance(item.name, bytes) else str(item.name or item.ordinal)
                    for item in entry.imports[:256]
                ],
            })
        data = {
            "machine": hex(int(pe.FILE_HEADER.Machine)),
            "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
            "entry_point": hex(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            "image_base": hex(int(pe.OPTIONAL_HEADER.ImageBase)),
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "sections": sections,
            "imports": imports,
            "has_authenticode_directory": bool(
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ].Size
            ),
        }
        pe.close()
        return _result(
            "pefile",
            "completed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=data,
        )
    except Exception as exc:  # parser failures are evidence limitations, not fatal
        return _result(
            "pefile",
            "failed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=str(exc),
        )


def _pdf_triage(path: Path) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=False)
        root = reader.trailer.get("/Root", {})
        if hasattr(root, "get_object"):
            root = root.get_object()
        names = root.get("/Names", {}) if hasattr(root, "get") else {}
        if hasattr(names, "get_object"):
            names = names.get_object()
        data = {
            "pages": len(reader.pages),
            "encrypted": bool(reader.is_encrypted),
            "metadata": {str(k): str(v)[:2000] for k, v in (reader.metadata or {}).items()},
            "has_javascript_name_tree": bool(
                hasattr(names, "get") and names.get("/JavaScript")
            ),
            "has_embedded_files": bool(
                hasattr(names, "get") and names.get("/EmbeddedFiles")
            ),
            "open_action_present": bool(
                hasattr(root, "get") and root.get("/OpenAction")
            ),
        }
        return _result(
            "pdf",
            "completed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            data=data,
        )
    except ImportError:
        return _result("pdf", "not_installed")
    except Exception as exc:
        return _result(
            "pdf",
            "failed",
            started_at=started_at,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=str(exc),
        )


def _is_registry_hive(path: Path, header: bytes) -> bool:
    return header.startswith(b"regf") or path.name.upper() in {
        "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT"
    }


def artifact_profile(path: str | Path, artifact_type: str = "evidence") -> dict:
    """Return deterministic file facts for the Forensic Planner Agent."""
    target = Path(path).resolve(strict=True)
    with target.open("rb") as handle:
        header = handle.read(64)
    suffix = target.suffix.lower()
    signatures = {
        "pe": header.startswith(b"MZ"),
        "elf": header.startswith(b"\x7fELF"),
        "pdf": header.startswith(b"%PDF"),
        "registry_hive": _is_registry_hive(target, header),
        "zip": header.startswith(b"PK\x03\x04"),
        "ole": header.startswith(bytes.fromhex("d0cf11e0a1b11ae1")),
        "ewf": suffix in {".e01", ".ex01"},
        "disk_image": suffix in {".e01", ".ex01", ".raw", ".dd", ".img", ".001"},
        "pcap": (
            header[:4] in {
                bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
                bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d"),
                bytes.fromhex("0a0d0d0a"),
            }
            or suffix in {".pcap", ".pcapng", ".cap"}
        ),
        "sqlite": (
            header.startswith(b"SQLite format 3\x00")
            or suffix in {".sqlite", ".sqlite3", ".db"}
        ),
    }
    return {
        "artifact": target.name,
        "artifact_type": artifact_type,
        "size_bytes": target.stat().st_size,
        "extension": suffix,
        "header_hex": header[:32].hex(),
        "signatures": signatures,
    }


def _execute_selected_tool(
    tool_id: str,
    target: Path,
    profile: dict,
    *,
    sha256: str,
    derived_dir: str | Path | None,
    parameters: dict[str, Any] | None,
) -> list[dict]:
    """Execute one planner-selected adapter with fixed safety boundaries."""
    parameters = parameters if isinstance(parameters, dict) else {}
    signatures = profile["signatures"]
    size = int(profile["size_bytes"])
    if tool_id in {"strings", "exiftool", "clamav"} and size > MAX_STATIC_FILE_BYTES:
        return [_result(
            tool_id,
            "skipped_bound",
            note=f"Artifact exceeds the static-analysis byte limit.",
        )]
    if tool_id == "file":
        return [_run("file", ["file", "-b", "--mime-type", str(target)])]
    if tool_id == "strings":
        return [_run(
            "strings",
            ["strings", "-a", "-n", str(STRINGS_MIN_LENGTH), str(target)],
        )]
    if tool_id == "exiftool":
        return [_run("exiftool", ["exiftool", "-json", "-G", "-n", str(target)])]
    if tool_id == "clamav":
        return [_run("clamav", ["clamscan", "--no-summary", "--infected", str(target)])]
    if tool_id == "pefile":
        return [
            _pe_triage(target)
            if signatures["pe"]
            else _result("pefile", "not_applicable", applicable=False)
        ]
    if tool_id == "pdf":
        return [
            _pdf_triage(target)
            if signatures["pdf"] or profile["extension"] == ".pdf"
            else _result("pdf", "not_applicable", applicable=False)
        ]
    if tool_id == "capa":
        command = ["capa", "-j"]
        if CAPA_RULES_DIR:
            command.extend(["-r", CAPA_RULES_DIR])
        command.append(str(target))
        return [_run("capa", command)]
    if tool_id == "floss":
        return [
            _run("floss", ["floss", "--json", str(target)])
            if signatures["pe"]
            else _result("floss", "not_applicable", applicable=False)
        ]
    if tool_id == "oletools":
        return [
            _run("oletools", ["oleid", str(target)]),
            _run("oletools", ["olevba", "--json", str(target)]),
        ]
    if tool_id == "ewf":
        return [
            _run("ewf", ["ewfinfo", str(target)])
            if signatures["ewf"]
            else _result("ewf", "not_applicable", applicable=False)
        ]
    if tool_id == "sleuthkit":
        return [
            _run("sleuthkit", ["mmls", str(target)])
            if signatures["disk_image"]
            else _result("sleuthkit", "not_applicable", applicable=False)
        ]
    if tool_id == "regripper":
        return [
            _run("regripper", ["regripper", "-r", str(target), "-a"])
            if signatures["registry_hive"]
            else _result("regripper", "not_applicable", applicable=False)
        ]
    if tool_id == "tshark":
        packet_cap = max(
            100,
            min(
                int(get_value("forensics", "packet_record_cap", default=5000)),
                100_000,
            ),
        )
        return [
            _run(
                "tshark",
                [
                    "tshark", "-n", "-r", str(target), "-c", str(packet_cap),
                    "-T", "fields", "-E", "header=y", "-E", "separator=\t",
                    "-e", "frame.number", "-e", "frame.time_epoch",
                    "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport",
                    "-e", "udp.srcport", "-e", "ip.dst", "-e", "ipv6.dst",
                    "-e", "tcp.dstport", "-e", "udp.dstport",
                    "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
                ],
            )
            if signatures["pcap"]
            else _result("tshark", "not_applicable", applicable=False)
        ]
    if tool_id == "sqlite":
        if not signatures["sqlite"]:
            return [_result("sqlite", "not_applicable", applicable=False)]
        return [
            _run(
                "sqlite",
                [
                    "sqlite3", "-readonly", str(target),
                    "PRAGMA quick_check; SELECT type,name,tbl_name,sql "
                    "FROM sqlite_master ORDER BY type,name LIMIT 1000;",
                ],
            )
        ]
    if tool_id == "volatility3":
        plugins = parameters.get("plugins")
        if not isinstance(plugins, list) or not plugins:
            return [_result(
                "volatility3",
                "invalid_plan",
                error="The Forensic Planner Agent did not select memory plugins.",
            )]
        jobs = []
        results = []
        for plugin in plugins:
            plugin_name = str(plugin).strip()
            if not plugin_name or not all(
                character.isalnum() or character in "._"
                for character in plugin_name
            ):
                results.append(_result(
                    "volatility3",
                    "invalid_plan",
                    error=f"Invalid plugin name: {plugin_name}",
                ))
                continue
            jobs.append(plugin_name)
        concurrency = max(1, min(
            len(jobs) or 1,
            internal_worker_limit("forensic", int(get_value(
                "forensics", "volatility_plugin_concurrency", default=2
            ))),
        ))
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [
                executor.submit(
                    _run,
                    "volatility3",
                    ["vol", "-q", "-f", str(target), "-r", "json", plugin],
                )
                for plugin in jobs
            ]
            results.extend(future.result() for future in futures)
        return results
    if tool_id == "yara":
        from services.detection import yara_engine
        scan = yara_engine.scan_paths([str(target)])
        return [_result(
            "yara",
            "completed",
            data=scan,
            note="Rule matches are evidence observations, not an automatic verdict.",
        )]
    return [_result(
        tool_id,
        "adapter_unavailable",
        note="The capability is catalogued but has no governed THOS adapter.",
    )]


def run_static_triage(
    path: str | Path,
    *,
    sha256: str,
    artifact_type: str = "suspicious_file",
    derived_dir: str | Path | None = None,
    tool_plan: list[dict[str, Any]] | None = None,
) -> dict:
    """Execute only tools selected by the validated Forensic Planner Agent."""
    target = Path(path).resolve(strict=True)
    profile = artifact_profile(target, artifact_type)
    catalog_ids = {str(item["tool_id"]) for item in _TOOL_CATALOG}
    accepted_plan: list[dict] = []
    for step in tool_plan or []:
        if not isinstance(step, dict):
            continue
        tool_id = str(step.get("tool_id") or "").strip()
        if tool_id not in catalog_ids:
            accepted_plan.append({
                "tool_id": tool_id or "unknown",
                "objective": "",
                "parameters": {},
                "_invalid": True,
            })
            continue
        accepted_plan.append({
            "tool_id": tool_id,
            "objective": str(step.get("objective") or "")[:1000],
            "parameters": step.get("parameters") if isinstance(
                step.get("parameters"), dict
            ) else {},
        })
    concurrency = max(1, min(
        len(accepted_plan) or 1,
        internal_worker_limit("forensic", int(get_value("forensics", "tool_concurrency", default=4))),
    ))

    def execute(step: dict[str, Any]) -> list[dict]:
        if step.get("_invalid"):
            return [_result(
                step["tool_id"],
                "invalid_plan",
                error="Planner selected a tool outside the capability catalog.",
            )]
        try:
            return _execute_selected_tool(
                step["tool_id"],
                target,
                profile,
                sha256=sha256,
                derived_dir=derived_dir,
                parameters=step["parameters"],
            )
        except Exception as exc:  # isolate one read-only adapter from peers
            return [_result(step["tool_id"], "failed", error=str(exc))]

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(execute, step) for step in accepted_plan]
        result_groups = [future.result() for future in futures]
    results = [item for group in result_groups for item in group]
    public_plan = [
        {key: value for key, value in step.items() if not key.startswith("_")}
        for step in accepted_plan
    ]
    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    evidence_observations = sum(
        1 for item in results
        if (
            item.get("tool_id") == "clamav"
            and item.get("exit_code") == 1
        )
    )
    for item in results:
        if item.get("tool_id") == "yara" and isinstance(item.get("data"), dict):
            evidence_observations += sum(
                len(result.get("matches") or [])
                for result in item["data"].get("results") or []
                if isinstance(result, dict)
            )
        if item.get("tool_id") == "virustotal" and isinstance(item.get("data"), dict):
            stats = item["data"].get("last_analysis_stats") or {}
            evidence_observations += int(stats.get("malicious", 0) or 0)
            evidence_observations += int(stats.get("suspicious", 0) or 0)
    return {
        "artifact": target.name,
        "artifact_type": artifact_type,
        "sha256": sha256,
        "size_bytes": profile["size_bytes"],
        "profile": profile,
        "tool_plan": public_plan,
        "summary": counts,
        "evidence_observation_count": evidence_observations,
        "results": results,
    }
