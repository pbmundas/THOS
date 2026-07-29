from services.api.ui_gateway import _clean_report_presentation


def test_historical_report_presentation_removes_icons_and_legacy_wording():
    source = """## 🚀 Phase 5
### 🔎 Investigation
- [⚠ circumstantial] Review this evidence.
✅ No pending approvals required.
Human approval is required before action.
"""

    cleaned = _clean_report_presentation(source)

    assert "🚀" not in cleaned
    assert "🔎" not in cleaned
    assert "⚠" not in cleaned
    assert "✅" not in cleaned
    assert "approval" not in cleaned.lower()
    assert "## Phase 5" in cleaned
    assert "[circumstantial]" in cleaned
    assert "analyst review" in cleaned.lower()


def test_historical_negative_claim_is_not_presented_as_hard_evidence():
    source = (
        "### Security Findings\n"
        "- [hard-evidence] No evidence of unauthorized outbound traffic "
        "(evidence: reviewed records; ref: 0-3)\n"
        "- [hard-evidence] Nmap execution observed (evidence: command; ref: 4)\n"
    )

    cleaned = _clean_report_presentation(source)

    assert "- [circumstantial] No evidence of unauthorized outbound traffic" in cleaned
    assert "- [hard-evidence] Nmap execution observed" in cleaned
