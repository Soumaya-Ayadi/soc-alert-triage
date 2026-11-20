"""Convertit /var/ossec/logs/alerts/alerts.json (vrai Wazuh, 1 JSON par ligne) en alertes pour l'agent.
Wazuh émet un événement par alerte : on regroupe les échecs SSH par IP pour calculer count, distinct_users, success_after_failures.
Usage : python wazuh_connector.py --file alerts.json --out data/wazuh_alerts.json"""
import argparse
import json
from datetime import datetime, timedelta

SSH_FAIL_GROUP = "authentication_failures"
SSH_SUCCESS_RULES = {"5715"}          # sshd: authentication success
FREQ_RULES = {"5763", "5712", "5551"}  # règles de corrélation (brute force) déjà agrégées par Wazuh


def _ts(a):  # "2026-11-20T10:15:03.123+0000"
    return datetime.strptime(a["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")


def convert(path: str, window_s: int = 300) -> list[dict]:
    raw = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    fails = [a for a in raw if SSH_FAIL_GROUP in a["rule"].get("groups", []) and a.get("data", {}).get("srcip")]
    succ = [a for a in raw if a["rule"]["id"] in SSH_SUCCESS_RULES and a.get("data", {}).get("srcip")]
    out = []
    for a in raw:
        r, d = a["rule"], a.get("data", {})
        base = {"id": a.get("id", a["timestamp"]), "timestamp": a["timestamp"], "scenario": "wazuh",
                "rule": {"id": r["id"], "level": r["level"], "description": r["description"],
                         "groups": r.get("groups", [])},
                "agent": a.get("agent", {}), "full_log": a.get("full_log", ""),
                "mitre_from_wazuh": r.get("mitre", {}).get("id", [])}
        ip = d.get("srcip")
        if SSH_FAIL_GROUP in r.get("groups", []) and r["id"] in FREQ_RULES and ip:
            t = _ts(a)
            same = [f for f in fails if f["data"]["srcip"] == ip and timedelta(0) <= t - _ts(f) <= timedelta(seconds=window_s)]
            users = {f["data"].get("dstuser") or f["data"].get("srcuser") for f in same}
            ok = any(s["data"]["srcip"] == ip and _ts(s) >= t for s in succ)
            base["data"] = {"srcip": ip, "count": max(len(same), 1), "distinct_users": len(users) or 1,
                            "success_after_failures": ok, "window": window_s}
            out.append(base)
        elif "web" in r.get("groups", []) and "attack" in r.get("groups", []) and ip:
            base["data"] = {"srcip": ip, "url": d.get("url", ""), "status": int(d.get("id", 0) or 0),
                            "user_agent": a.get("data", {}).get("user_agent", ""), "count": 1}
            out.append(base)
        elif "syscheck" in r.get("groups", []):
            sc = a.get("syscheck", {})
            base["data"] = {"path": sc.get("path", ""), "process": a.get("syscheck", {}).get("audit", {}).get("process", {}).get("name", "")}
            out.append(base)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--out", default="data/wazuh_alerts.json")
    a = ap.parse_args()
    alerts = convert(a.file)
    json.dump(alerts, open(a.out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"{len(alerts)} alertes converties -> {a.out}")
