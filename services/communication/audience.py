from services.orchestration.state import HuntState


async def communicate_node(state: HuntState) -> dict:
    """Keep one evidence set while making the headline fit its audience."""
    summary = state.get("reasoning_summary") or "No summary was produced."
    style = str(state.get("cover_style") or "1")
    if style == "2":
        text = f"SOC analyst brief: {summary} Verify cited records and the verifier result before containment."
    elif style == "3":
        text = f"Compliance brief: {summary} Retain this report, cited evidence, verifier outcome, and approval record for audit."
    else:
        text = f"Executive brief: {summary} No automated response action is taken by THOS."
    return {"communication_summary": text}
