"""Analyse un fichier d'alertes (ex. data/wazuh_alerts.json) : python analyze_file.py data/wazuh_alerts.json [--backend ollama] [--memory]"""
import argparse
import json
from soc_agent.agent import analyze
from soc_agent.memory import IncidentMemory

ap = argparse.ArgumentParser()
ap.add_argument("file"); ap.add_argument("--backend", default="mock"); ap.add_argument("--memory", action="store_true")
a = ap.parse_args()
mem = IncidentMemory() if a.memory else None
for alert in json.load(open(a.file, encoding="utf-8")):
    print(analyze(alert, a.backend, True, memory=mem)["report"], "\n")
