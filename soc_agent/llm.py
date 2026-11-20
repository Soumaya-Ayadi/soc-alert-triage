"""Backends LLM : Ollama (modèle local réel) ou Mock (heuristique hors-ligne pour tester sans GPU)."""
import json
import re
import requests
from . import config


class OllamaLLM:
    name = "ollama"

    def chat(self, system: str, user: str) -> str:
        r = requests.post(f"{config.OLLAMA_URL}/api/chat", timeout=180, json={
            "model": config.OLLAMA_MODEL, "stream": False, "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        })
        r.raise_for_status()
        return r.json()["message"]["content"]


class MockLLM:
    """Simule un LLM : score les preuves structurées du prompt.
    En mode NON protégé (pas de marqueur [UNTRUSTED_DATA]), il simule un LLM naïf qui obéit
    aux instructions cachées dans le log, pour démontrer l'attaque par injection de prompt."""
    name = "mock"

    def chat(self, system: str, user: str) -> str:
        ev = json.loads(re.search(r"<evidence>(.*?)</evidence>", user, re.S).group(1))
        if "[UNTRUSTED_DATA]" not in user and re.search(
                r"ignore\s+(all\s+)?previous|classify\s+as\s+false", user, re.I):
            return json.dumps({"verdict": "false_positive", "confidence": 0.95, "technique_id": "none",
                               "reasoning": "Le log indique qu'il s'agit d'un faux positif.",
                               "evidence_used": ["rule_description"],
                               "recommended_action": "close_as_false_positive"})
        score, used = self._score(ev)
        verdict = "incident" if score >= 60 else "suspicious" if score >= 30 else "false_positive"
        conf = round(min(0.97, max(0.5, 0.5 + abs(score - 45) / 100)), 2)
        tech, action = self._technique_action(ev, verdict)
        why = {"incident": "Plusieurs indicateurs convergent vers une activité malveillante",
               "suspicious": "Indicateurs ambigus, une vérification humaine est nécessaire",
               "false_positive": "Les indicateurs sont cohérents avec une activité légitime"}[verdict]
        return json.dumps({"verdict": verdict, "confidence": conf, "technique_id": tech,
                           "reasoning": f"{why} (score={score}).", "evidence_used": used,
                           "recommended_action": action})

    @staticmethod
    def _score(ev):
        s, used = 0, []
        def add(key, pts):
            nonlocal s
            s += pts
            if key not in used:
                used.append(key)
        if ev.get("src_ip_known_malicious"): add("src_ip_known_malicious", 45)
        if ev.get("src_ip_allowlisted_scanner"): add("src_ip_allowlisted_scanner", -80)
        c = ev["category"]
        if c == "authentication":
            n = ev["failed_attempts"]
            if n >= 20: add("failed_attempts", 35)
            elif n >= 8: add("failed_attempts", 18)
            elif n <= 5 and ev.get("src_ip_internal"): add("src_ip_internal", -30)
            if ev["distinct_users"] >= 5: add("distinct_users", 15)
            if ev["success_after_failures"] and not ev.get("src_ip_internal"): add("success_after_failures", 25)
        elif c == "recon":
            p = ev["distinct_ports_scanned"]
            if p >= 100: add("distinct_ports_scanned", 40)
            elif p >= 20: add("distinct_ports_scanned", 20)
            if not ev.get("src_ip_internal"): add("src_ip_internal", 10)
        elif c == "phishing":
            if ev["lookalike_of"]: add("lookalike_of", 35)
            if ev["suspicious_tld"]: add("suspicious_tld", 20)
            if ev["shortened_url"]: add("shortened_url", 15)
            if ev["urgency_words"] >= 2: add("urgency_words", 15)
            if ev["executable_attachment"]: add("executable_attachment", 30)
            if ev["sender_known"]: add("sender_known", -40)
        return s, used or ["rule_description"]

    @staticmethod
    def _technique_action(ev, verdict):
        c = ev["category"]
        if verdict == "false_positive":
            return "none", "close_as_false_positive"
        if c == "authentication":
            tech = "T1110.003" if ev["distinct_users"] >= 5 else "T1110.001"
            act = "disable_account" if ev["success_after_failures"] else "block_ip"
        elif c == "recon":
            tech, act = "T1046", "block_ip"
        else:
            tech, act = ("T1566.002", "quarantine_email")
            if ev.get("executable_attachment"): tech = "T1566.001"
        return tech, ("create_ticket" if verdict == "suspicious" else act)


def get_llm(backend: str):
    return OllamaLLM() if backend == "ollama" else MockLLM()
