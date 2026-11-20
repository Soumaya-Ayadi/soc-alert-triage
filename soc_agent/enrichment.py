"""Enrichissement : transforme une alerte en preuves structurées (evidence)."""
import difflib
import re
import requests
from . import config

KNOWN_BAD_IPS = {  # mini base locale de threat intel (plages de documentation)
    "203.0.113.7": 95, "203.0.113.45": 88, "203.0.113.99": 92,
    "198.51.100.23": 80, "198.51.100.77": 85, "198.51.100.200": 90,
}
BRANDS = ["microsoft.com", "google.com", "paypal.com", "amazon.com", "company.com"]
KNOWN_SENDERS = {"newsletter.github.com", "company.com", "notifications.linkedin.com", "microsoft.com"}
BAD_TLDS = (".top", ".xyz", ".click", ".zip", ".work")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl")
URGENCY = ["urgent", "immediately", "verify", "suspended", "password", "action required", "within 24"]


def _normalize(domain: str) -> str:
    return domain.translate(str.maketrans("0135", "oies")).replace("-", "")


def _lookalike(domain: str):
    if domain in BRANDS:
        return None
    for b in BRANDS:
        if difflib.SequenceMatcher(None, _normalize(domain), b).ratio() > 0.75 or b.split(".")[0] in _normalize(domain):
            return b
    return None


def _ip_reputation(ip: str) -> int:
    if ip in KNOWN_BAD_IPS:
        return KNOWN_BAD_IPS[ip]
    if config.ABUSEIPDB_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", timeout=5,
                             headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90})
            return int(r.json()["data"]["abuseConfidenceScore"])
        except Exception:
            pass
    return 0


def enrich(alert: dict) -> dict:
    rule, data = alert["rule"], alert.get("data", {})
    groups = rule.get("groups", [])
    ev = {"rule_level": rule["level"], "rule_description": rule["description"]}
    ev["category"] = ("authentication" if "authentication_failures" in groups else
                      "recon" if "recon" in groups else
                      "phishing" if "phishing" in groups else "other")

    ip = data.get("srcip")
    if ip:
        ev["src_ip_internal"] = ip.startswith(config.INTERNAL_PREFIXES)
        ev["src_ip_allowlisted_scanner"] = ip in config.ALLOWLISTED_SCANNERS
        ev["src_ip_reputation"] = _ip_reputation(ip)
        ev["src_ip_known_malicious"] = ev["src_ip_reputation"] >= 50

    if ev["category"] == "authentication":
        ev["failed_attempts"] = data.get("count", 0)
        ev["distinct_users"] = data.get("distinct_users", 1)
        ev["success_after_failures"] = data.get("success_after_failures", False)
        ev["window_seconds"] = data.get("window", 0)
    elif ev["category"] == "recon":
        ev["distinct_ports_scanned"] = data.get("ports", 0)
        ev["window_seconds"] = data.get("window", 0)
    elif ev["category"] == "phishing":
        dom = data.get("sender", "@").split("@")[-1].lower()
        ev["sender_domain"] = dom
        ev["sender_known"] = dom in KNOWN_SENDERS
        ev["lookalike_of"] = _lookalike(dom)
        ev["suspicious_tld"] = dom.endswith(BAD_TLDS)
        url = data.get("url", "")
        ev["shortened_url"] = any(s in url for s in SHORTENERS)
        subj = data.get("subject", "").lower()
        ev["urgency_words"] = sum(w in subj for w in URGENCY)
        ev["executable_attachment"] = bool(re.search(r"\.(exe|scr|js|vbs|bat|iso)$", data.get("attachment", ""), re.I))
    return ev
