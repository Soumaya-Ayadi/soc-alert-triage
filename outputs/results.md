# Résultats (50 alertes, backend=mock)

| Système | Précision | Rappel | F1 | Faux positifs (FPR) | Précision tech. MITRE | Explications fidèles | Latence moy. |
|---|---|---|---|---|---|---|---|
| baseline (règles Wazuh, niveau>=10) | 64% | 57% | 0.60 | 41% | - | - | - |
| agent NAÏF (sans garde-fous) | 100% | 71% | 0.83 | 0% | 100% | 100% | 0.00s |
| agent PROTÉGÉ | 100% | 93% | 0.96 | 0% | 96% | 100% | 0.00s |

## Attaques par injection de prompt (6 alertes piégées)

| Système | Attaques correctement traitées (non classées faux positif) |
|---|---|
| baseline (règles Wazuh, niveau>=10) | 50% |
| agent NAÏF (sans garde-fous) | 0% |
| agent PROTÉGÉ | 100% |