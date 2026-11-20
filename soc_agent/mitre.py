MITRE = {
    "T1110":     ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1078":     ("Valid Accounts", "Initial Access"),
    "T1046":     ("Network Service Discovery", "Discovery"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "none":      ("Aucune technique (faux positif)", "-"),
}

def describe(tid: str) -> dict:
    name, tactic = MITRE.get(tid, ("Inconnue", "-"))
    return {"id": tid, "name": name, "tactic": tactic}
