# Agent SOC de triage d'alertes : agentique + génératif + explicable

Projet académique : un agent IA qui reçoit des alertes de type Wazuh, les enrichit, les classe
(`incident` / `suspicious` / `false_positive`), les relie à **MITRE ATT&CK**, explique sa décision
et propose une action de réponse validée par un humain. Il résiste aux **injections de prompt**.

## Les 3 « plus »
| Plus | Où |
|---|---|
| **1. Explicabilité (XAI)** | `agent.py` : preuves citées, confiance, MITRE, vérification de fidélité (chaque preuve citée doit exister) |
| **2. Évaluation chiffrée** | `evaluate.py` : précision, rappel, F1, FPR vs baseline Wazuh |
| **3. Démo de sécurité** | `guardrails.py` + `demo.py` : agent naïf vs agent protégé face à un log piégé |

## Architecture
```
Alerte SIEM -> garde-fous (détection + sanitisation) -> enrichissement (IP, e-mail)
 -> LLM (JSON strict) -> validation du schéma -> politique déterministe
 -> rapport explicable -> validation humaine -> action (simulée)
```

## Installation
```bash
pip install -r requirements.txt
python data/generate_dataset.py          # 50 alertes simulées avec vérité terrain
python evaluate.py                       # évaluation (backend mock, sans GPU)
python demo.py                           # démo attaque par injection : naïf vs protégé
streamlit run app.py                     # tableau de bord
```

## Utiliser un vrai LLM local (recommandé pour le rendu final)
```bash
# installer Ollama (ollama.com), puis :
ollama pull llama3.1:8b
python evaluate.py --backend ollama
python demo.py --backend ollama
# optionnel : export OLLAMA_MODEL=mistral ; export ABUSEIPDB_KEY=...
```
**Important :** le backend `mock` est une heuristique écrite par nous pour tester le pipeline hors-ligne.
Ses chiffres ne prouvent pas la performance d'un LLM. Les résultats à présenter dans le rapport
sont ceux obtenus avec `--backend ollama`.

## Brancher un vrai Wazuh (étape bonus)
Installer Wazuh + une VM victime, simuler un brute force SSH (`hydra` depuis Kali, ou Atomic Red Team),
récupérer l'alerte depuis `/var/ossec/logs/alerts/alerts.json` ou l'API Wazuh, et la passer à
`analyze()` : le format utilisé ici est une version simplifiée de ce JSON.

## Structure
```
soc_agent/  config, mitre, guardrails, enrichment, llm, agent, actions
data/       generate_dataset.py -> alerts.json
evaluate.py demo.py app.py
```

## Limites (à mentionner dans le rapport)
- Données simulées, petit jeu de test (50 alertes) : les résultats sont indicatifs.
- Les garde-fous par motifs (regex) ne couvrent pas toutes les injections ; la politique déterministe et l'humain dans la boucle sont la vraie défense.
- Actions de réponse simulées. Aucune action critique sans validation humaine.
- Un LLM local de 7-8B peut se tromper sur les sorties structurées : d'où validation du schéma, retry et escalade.

## Pistes d'amélioration
Mémoire des incidents passés (ChromaDB), corrélation multi-alertes, connexion TheHive/Shuffle, plus de scénarios.
