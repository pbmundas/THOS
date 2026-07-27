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
