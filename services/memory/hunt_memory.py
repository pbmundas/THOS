from services.observability import audit
from services.orchestration.state import HuntState


async def recall_hunt_memory_node(state: HuntState) -> dict:
    technique = state.get("technique_id") or ""
    if not technique:
        return {"hunt_memory": []}
    return {"hunt_memory": await audit.recent_hunt_memory(technique)}
