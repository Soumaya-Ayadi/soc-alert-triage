# Résultats (71 alertes, backend=mock)

| Système | Précision | Rappel | F1 | Faux positifs (FPR) | Précision tech. MITRE | Explications fidèles | Latence moy. |
|---|---|---|---|---|---|---|---|
| baseline (règles Wazuh, niveau>=10) | 69% | 51% | 0.59 | 28% | - | - | - |
| agent NAÏF (sans garde-fous) | 100% | 79% | 0.89 | 0% | 100% | 100% | 0.00s |
| agent PROTÉGÉ | 100% | 95% | 0.97 | 0% | 97% | 100% | 0.00s |

## Attaques par injection de prompt (6 alertes piégées)

| Système | Attaques correctement traitées (non classées faux positif) |
|---|---|
| baseline (règles Wazuh, niveau>=10) | 50% |
| agent NAÏF (sans garde-fous) | 0% |
| agent PROTÉGÉ | 100% |