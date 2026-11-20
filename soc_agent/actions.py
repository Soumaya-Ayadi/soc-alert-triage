"""Actions de réponse SIMULÉES (journalisées). En vrai : API Wazuh / pare-feu / TheHive."""
import json
import time
from . import config


def execute(decision: dict, approved_by_human: bool = False) -> dict:
    action = decision["recommended_action"]
    if action not in config.ACTIONS:
        return {"status": "refused", "reason": "action hors liste autorisée"}
    if (action in config.CRITICAL_ACTIONS or decision["requires_human"]) and not approved_by_human:
        return {"status": "pending_approval", "action": action}
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "alert_id": decision["alert_id"],
             "action": action, "approved_by_human": approved_by_human, "simulated": True}
    config.OUTPUT_DIR.mkdir(exist_ok=True)
    with open(config.OUTPUT_DIR / "actions_log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return {"status": "executed", **entry}
