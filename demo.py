"""Démo en ligne de commande : python demo.py [--backend ollama] [--id ALT-001]"""
import argparse
import json
from soc_agent import config
from soc_agent.agent import analyze

ap = argparse.ArgumentParser()
ap.add_argument("--backend", default="mock")
ap.add_argument("--id", default=None, help="id d'alerte ; par défaut : une alerte avec injection de prompt")
a = ap.parse_args()
alerts = json.loads(config.DATASET.read_text(encoding="utf-8"))
alert = next(x for x in alerts if (x["id"] == a.id if a.id else x["ground_truth"]["injection"]))
print("ALERTE :", alert["full_log"][:200], "\n")
for prot in (False, True):
    print("=" * 70, f"\nAGENT {'PROTÉGÉ' if prot else 'NAÏF (sans garde-fous)'}\n")
    print(analyze(alert, a.backend, prot)["report"], "\n")
