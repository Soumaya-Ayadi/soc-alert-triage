"""Mémoire des incidents passés (ChromaDB, local). Stocke uniquement des RÉSUMÉS structurés
(jamais le log brut) + le verdict validé par un analyste, pour éviter de ré-injecter du contenu non fiable."""
import hashlib
import math
import re
import chromadb
from . import config

DIM = 256


def _doc(evidence: dict) -> str:
    """Résumé textuel des preuves ; les nombres sont mis en classes (log2) pour que 40 et 60 se ressemblent."""
    parts = []
    for k, v in sorted(evidence.items()):
        if k.startswith("memory_") or k in ("rule_description", "sender_domain"):
            continue
        if isinstance(v, bool) or v is None or isinstance(v, str):
            parts.append(f"{k}={v}")
        else:
            parts.append(f"{k}~{int(math.log2(v + 1))}")
    return " ".join(parts)


def _hash_embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for tok in re.findall(r"[^\s]+", text):
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        vec[h % DIM] += 1.0 if (h >> 8) % 2 else -1.0
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


class IncidentMemory:
    def __init__(self, path=None, reset: bool = False):
        self.client = chromadb.PersistentClient(path=str(path or config.MEMORY_DIR))
        if reset:
            try:
                self.client.delete_collection("incidents")
            except Exception:
                pass
        self.col = self.client.get_or_create_collection("incidents", metadata={"hnsw:space": "cosine"})
        self.use_hash = config.MEMORY_EMBED == "hash"

    def _embed(self, text):
        return _hash_embed(text) if self.use_hash else None

    def add(self, alert_id: str, evidence: dict, analyst_verdict: str, technique: str = "none"):
        """À appeler quand un analyste confirme ou corrige une décision."""
        doc = _doc(evidence)
        kw = {"embeddings": [self._embed(doc)]} if self.use_hash else {}
        self.col.upsert(ids=[alert_id], documents=[doc], metadatas=[
            {"verdict": analyst_verdict, "technique": technique, "category": evidence.get("category", "")}], **kw)

    def similar(self, evidence: dict, k: int = 3, min_similarity: float = 0.80) -> list[dict]:
        if self.col.count() == 0:
            return []
        doc = _doc(evidence)
        kw = {"query_embeddings": [self._embed(doc)]} if self.use_hash else {"query_texts": [doc]}
        r = self.col.query(n_results=min(k, self.col.count()),
                           where={"category": evidence.get("category", "")}, **kw)
        out = []
        for i, dist, meta in zip(r["ids"][0], r["distances"][0], r["metadatas"][0]):
            sim = 1 - dist
            if sim >= min_similarity:
                out.append({"alert_id": i, "verdict": meta["verdict"], "technique": meta["technique"], "similarity": sim})
        return out
