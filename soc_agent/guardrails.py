"""Défense contre l'injection de prompt : le contenu des logs est une DONNÉE, jamais une instruction."""
import re

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above|rules)",
    r"you\s+are\s+now\b",
    r"system\s*prompt",
    r"classify\s+(this\s+)?(alert\s+)?as\b",
    r"mark\s+(this\s+)?(as\s+)?(benign|false[\s_]positive|safe)",
    r"do\s+not\s+(alert|escalate|report|block)",
    r"(assistant|system)\s*:",
    r"take\s+no\s+action",
]
_RX = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
MAX_FIELD_LEN = 400


def detect_injection(text: str) -> list[str]:
    return [rx.pattern for rx in _RX if rx.search(text or "")]


def sanitize(text: str) -> str:
    """Retire les caractères de contrôle, neutralise les balises, tronque."""
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text or "")
    text = text.replace("<", "‹").replace(">", "›")
    return text[:MAX_FIELD_LEN]
