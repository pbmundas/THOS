import subprocess

from services.forensics import analysis, tools


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
