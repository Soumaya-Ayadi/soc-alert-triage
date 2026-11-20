"""Démo de la mémoire : un analyste valide des cas, l'agent retrouve les cas similaires ensuite."""
import json
from soc_agent import config
from soc_agent.agent import analyze
from soc_agent.enrichment import enrich
from soc_agent.memory import IncidentMemory

alerts = json.loads(config.DATASET.read_text(encoding="utf-8"))
benign = [a for a in alerts if a["scenario"] == "ssh_bruteforce" and a["ground_truth"]["label"] == "false_positive"]
mem = IncidentMemory(path=config.OUTPUT_DIR / "memory_demo", reset=True)
target, taught = benign[-1], benign[:-1][:3]
print("Alerte à analyser :", target["id"], "-", target["full_log"][:90], "\n")
print("--- SANS mémoire ---\n", analyze(target, "mock", True)["report"], "\n")
for a in taught:  # l'analyste confirme : faux positif
    mem.add(a["id"], enrich(a), "false_positive")
print(f"L'analyste valide {len(taught)} cas similaires comme faux positifs...\n")
print("--- AVEC mémoire ---\n", analyze(target, "mock", True, memory=mem)["report"])
