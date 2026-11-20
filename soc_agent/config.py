import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "outputs"
DATASET = ROOT / "data" / "alerts.json"

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")  # optionnel (API gratuite)

INTERNAL_PREFIXES = tuple(os.getenv("INTERNAL_PREFIXES", "10.,192.168.,172.16.").split(","))
ALLOWLISTED_SCANNERS = {"10.0.0.50"}  # scanner de vulnérabilités interne autorisé

VERDICTS = ["incident", "suspicious", "false_positive"]
ACTIONS = ["none", "close_as_false_positive", "create_ticket",
           "quarantine_email", "block_ip", "disable_account", "isolate_host"]
CRITICAL_ACTIONS = {"block_ip", "disable_account", "isolate_host"}  # validation humaine obligatoire
CONFIDENCE_THRESHOLD = 0.70

# --- Labo réel : IP de ta VM Kali à traiter comme "connue malveillante" (threat intel simulée) ---
EXTRA_BAD_IPS = {ip.strip() for ip in os.getenv("EXTRA_BAD_IPS", "").split(",") if ip.strip()}

# --- Mémoire des incidents (ChromaDB, 100 % local) ---
MEMORY_DIR = OUTPUT_DIR / "memory"
MEMORY_EMBED = os.getenv("MEMORY_EMBED", "hash")  # "hash" = hors-ligne ; "default" = MiniLM (téléchargé 1 fois)
