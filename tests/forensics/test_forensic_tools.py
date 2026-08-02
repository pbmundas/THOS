import asyncio
import subprocess

from services.forensics import analysis, interpretation, planner, tools


def test_command_adapter_never_uses_shell_and_caps_output(monkeypatch, tmp_path):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b"A" * 128)

    monkeypatch.setattr(tools.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    monkeypatch.setattr(tools, "TOOL_OUTPUT_BYTES", 32)

    result = tools._run("file", ["file", "-b", "evidence.bin"])

    assert captured["shell"] is False
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["argv"][0] == "/usr/bin/file"
    assert len(result["output"]) == 32
    assert result["truncated"] is True


def test_pe_artifact_is_content_routed_without_executing_sample(monkeypatch, tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    commands = []

    def fake_run(tool_id, command, timeout=None):
        commands.append((tool_id, command, timeout))
        return tools._result(tool_id, "completed")

    monkeypatch.setattr(tools, "_run", fake_run)
    monkeypatch.setattr(
        tools, "_pe_triage", lambda _path: tools._result("pefile", "completed")
    )
    result = tools.run_static_triage(
        sample,
        sha256="a" * 64,
        artifact_type="suspicious_file",
        derived_dir=tmp_path / "derived",
        tool_plan=[
            {
                "tool_id": tool_id,
                "objective": "Test the selected adapter.",
            }
            for tool_id in (
                "file", "strings", "exiftool", "clamav", "pefile",
                "capa", "floss",
            )
        ],
    )

    invoked = {item[0] for item in commands}
    assert {"file", "strings", "exiftool", "clamav", "capa", "floss"} <= invoked
    assert result["profile"]["signatures"]["pe"] is True
    assert all(command[1][0] != str(sample) for command in commands)


def test_tool_status_hides_tools_that_are_not_installed(monkeypatch):
    monkeypatch.setattr(tools, "_available", lambda _selector: False)

    assert tools.tool_status()["tools"] == []


def test_tool_status_hides_non_ready_catalog_states_even_if_binary_exists(monkeypatch):
    monkeypatch.setattr(tools, "_available", lambda _selector: True)
    monkeypatch.setattr(tools, "_TOOL_CATALOG", (
        {
            "tool_id": "ready",
            "name": "Ready",
            "availability": "command:ready",
            "deployment": "bundled",
        },
        {
            "tool_id": "licensed",
            "name": "Licensed",
            "availability": "command:licensed",
            "deployment": "license_required",
        },
        {
            "tool_id": "legacy",
            "name": "Legacy",
            "availability": "command:legacy",
            "deployment": "deprecated",
            "execution": "status_only",
        },
        {
            "tool_id": "wrong-platform",
            "name": "Wrong platform",
            "availability": "command:wrong-platform",
            "deployment": "unsupported_platform",
        },
    ))

    status = tools.tool_status()

    assert [item["tool_id"] for item in status["tools"]] == ["ready"]
    assert all(item["available"] is True for item in status["tools"])
    assert all(item["status"] == "available" for item in status["tools"])


def test_clamav_signature_result_becomes_a_fact_not_an_auto_verdict(monkeypatch):
    monkeypatch.setattr(
        analysis.ioc_management,
        "load_blocklist",
        lambda: {"indicators": {}},
    )
    triage = {
        "records": [],
        "inventory": [{
            "evidence_id": "E0001",
            "original_name": "sample.exe",
            "path": "/case/sample.exe",
        }],
        "static_analysis": [{
            "evidence_id": "E0001",
            "artifact": "sample.exe",
            "sha256": "a" * 64,
            "results": [{
                "tool_id": "clamav",
                "status": "completed",
                "exit_code": 1,
                "output": "sample.exe: Example.Signature FOUND",
            }],
        }],
    }

    result = analysis.correlate_evidence(triage)

    fact = next(
        item for item in result["evidence_facts"]
        if item["tool_id"] == "clamav"
    )
    assert fact["status"] == "completed"
    assert fact["evidence_refs"] == ["E0001"]
    assert result["activity_assessments"] == []


def test_forensic_planner_model_owns_capability_complete_tool_selection(
    monkeypatch, tmp_path
):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    captured = {}
    monkeypatch.setattr(planner, "tool_status", lambda: {
        "tools": [
            {"tool_id": "file", "status": "available", "capabilities": ["identify", "file"]},
            {"tool_id": "pefile", "status": "available", "capabilities": ["pe", "static"]},
        ]
    })

    async def fake_decide_json(**kwargs):
        captured.update(kwargs)
        return kwargs["validator"]({
            "case_objective": "Identify and structurally examine the executable.",
            "analysis_strategy": "rapid",
            "artifacts": [{
                "evidence_id": "E0001",
                "reasoning": "Content identification and PE structure answer the first-pass questions.",
                "required_capabilities": ["identify", "pe"],
                "deferred_tools": [],
                "tools": [
                    {"tool_id": "file", "objective": "Confirm the content type.", "plugins": []},
                    {"tool_id": "pefile", "objective": "Inspect PE structure.", "plugins": []},
                ],
            }],
        })

    monkeypatch.setattr(planner, "decide_json", fake_decide_json)
    result = asyncio.run(planner.plan_forensic_tools({
        "evidence": [{
            "evidence_id": "E0001",
            "original_name": "sample.exe",
            "sha256": "a" * 64,
            "path": str(sample),
            "artifact_type": "suspicious_file",
        }],
    }))

    assert captured["agent"] == "forensic_planner"
    assert captured["attempts"] == 2
    assert captured["transport_retries"] == 0
    assert result["analysis_strategy"] == "rapid"
    assert result["artifacts"][0]["required_capabilities"] == ["identify", "pe"]
    assert [item["tool_id"] for item in result["artifacts"][0]["tools"]] == ["file", "pefile"]


def test_model_selected_pcap_and_sqlite_adapters_are_content_gated(
    monkeypatch, tmp_path
):
    pcap = tmp_path / "capture.bin"
    pcap.write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 64)
    database = tmp_path / "browser-cache.bin"
    database.write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    commands = []

    def fake_run(tool_id, command, timeout=None):
        commands.append((tool_id, command, timeout))
        return tools._result(tool_id, "completed")

    monkeypatch.setattr(tools, "_run", fake_run)
    pcap_result = tools.run_static_triage(
        pcap,
        sha256="a" * 64,
        tool_plan=[{"tool_id": "tshark", "objective": "Parse packets."}],
    )
    sqlite_result = tools.run_static_triage(
        database,
        sha256="b" * 64,
        tool_plan=[{"tool_id": "sqlite", "objective": "Inventory schema."}],
    )

    assert pcap_result["profile"]["signatures"]["pcap"] is True
    assert sqlite_result["profile"]["signatures"]["sqlite"] is True
    tshark = next(command for tool_id, command, _timeout in commands if tool_id == "tshark")
    sqlite = next(command for tool_id, command, _timeout in commands if tool_id == "sqlite")
    assert tshark[:4] == ["tshark", "-n", "-r", str(pcap)]
    assert "-c" in tshark
    assert sqlite[:3] == ["sqlite3", "-readonly", str(database)]


def test_interpretation_package_keeps_material_facts_and_referenced_records(
    monkeypatch
):
    limits = {
        "interpretation_record_cap": 3,
        "interpretation_record_char_cap": 200,
        "interpretation_fact_cap": 2,
        "interpretation_fact_char_cap": 200,
    }
    monkeypatch.setattr(
        interpretation,
        "get_value",
        lambda _section, key, default=None: limits.get(key, default),
    )
    records = [
        {"_record_ref": f"E0001:{index}", "detail": f"event-{index}"}
        for index in range(10)
    ]
    facts = [
        {
            "fact_id": f"F{index}",
            "fact_type": "tool_observation",
            "status": "completed",
            "evidence_refs": [f"E0001:{index}"],
        }
        for index in range(4)
    ]
    facts.append({
        "fact_id": "F-MATERIAL",
        "fact_type": "yara_rule_match",
        "status": "completed",
        "evidence_refs": ["E0001:9"],
    })

    package = interpretation._bounded_evidence_package(
        {"records": records, "inventory": [], "warnings": []},
        {"evidence_facts": facts, "event_histogram": {}},
    )

    assert len(package["evidence_facts"]) == 2
    assert package["evidence_facts"][0]["fact_id"] == "F-MATERIAL"
    assert len(package["records"]) == 3
    assert package["records"][0]["_record_ref"] == "E0001:9"
    assert package["resource_bounds"] == {
        "total_records": 10,
        "records_supplied": 3,
        "records_omitted": 7,
        "total_facts": 5,
        "facts_supplied": 2,
        "facts_omitted": 3,
        "total_inventory_items": 0,
        "inventory_items_supplied": 0,
        "inventory_items_omitted": 0,
    }
