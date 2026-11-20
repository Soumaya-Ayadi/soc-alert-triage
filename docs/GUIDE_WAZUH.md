# Guide : installer Wazuh et générer une vraie alerte (brute force SSH)

> Tout se passe dans un **labo isolé sur ton PC**. N'attaque jamais une machine qui ne t'appartient pas.

## 0. Matériel
- PC avec 16 Go de RAM (8 Go possible mais serré), 60 Go de disque, VirtualBox installé.
- 3 machines virtuelles :

| VM | OS | RAM | Rôle |
|---|---|---|---|
| `wazuh` | Ubuntu Server 22.04 | 4 à 6 Go, 2 CPU | Serveur Wazuh (SIEM + dashboard) |
| `victime` | Ubuntu Server 22.04 | 1 à 2 Go | Machine surveillée (agent Wazuh + serveur SSH) |
| `kali` | Kali Linux | 2 Go | Attaquant |

Alternative plus rapide : télécharger l'**OVA Wazuh** (VM prête à l'emploi) sur la doc officielle et l'importer dans VirtualBox, ce qui évite l'étape 2.

## 1. Réseau du labo
Dans VirtualBox : Fichier > Outils > Gestionnaire de réseau > **Réseau NAT** (créer un réseau, ex. `10.0.2.0/24`), puis mettre les 3 VM sur ce réseau.
Note l'IP de chaque VM avec `ip a`. Vérifie qu'elles se voient (`ping`).

## 2. Installer Wazuh (sur la VM `wazuh`)
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
À la fin, le script affiche l'utilisateur `admin` et un **mot de passe : note-le**.
Ouvre `https://IP_DE_LA_VM_WAZUH` dans le navigateur (avertissement de certificat : normal en labo).
Vérifie les prérequis et la version actuelle sur documentation.wazuh.com (section Quickstart).

## 3. Installer l'agent sur la VM `victime`
1. Dashboard Wazuh > **Agents > Deploy new agent**.
2. Choisis Linux (DEB amd64), saisis l'IP du serveur Wazuh, donne le nom `victime`.
3. Copie-colle les commandes affichées sur la VM victime (elles installent et démarrent l'agent).
4. Vérifie que l'agent apparaît **Active** dans le dashboard.

Installe aussi le serveur SSH sur la victime et crée un utilisateur test :
```bash
sudo apt install -y openssh-server
sudo adduser testuser          # mot de passe simple, ex. : password123
```
Active l'authentification par mot de passe dans `/etc/ssh/sshd_config` (`PasswordAuthentication yes`), puis `sudo systemctl restart ssh`.

## 4. Générer une vraie alerte : brute force SSH (depuis `kali`)
```bash
# liste de mots de passe : rockyou est fournie avec Kali
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
head -200 /usr/share/wordlists/rockyou.txt > mini.txt     # 200 essais suffisent
hydra -l testuser -P mini.txt ssh://IP_VICTIME -t 4
```
Dans le dashboard Wazuh > **Threat Hunting / Events** : cherche `sshd`. Tu dois voir des alertes
« authentication failed » (règle 5760, niveau 5) puis « brute force » (règle 5763, niveau 10).
Les numéros de règles peuvent varier : repère-les dans ton propre dashboard.

## 5. Brancher l'agent IA sur cette alerte
Les alertes brutes sont dans `/var/ossec/logs/alerts/alerts.json` **sur la VM `wazuh`** (1 JSON par ligne).
```bash
# depuis ta machine de dev (ou la VM wazuh si tu y mets le projet)
scp utilisateur@IP_WAZUH:/var/ossec/logs/alerts/alerts.json ./alerts_wazuh.json   # peut demander sudo/chmod
python wazuh_connector.py --file alerts_wazuh.json --out data/wazuh_alerts.json
EXTRA_BAD_IPS=IP_KALI python analyze_file.py data/wazuh_alerts.json            # ajoute --backend ollama pour le vrai LLM
```
**Pourquoi `EXTRA_BAD_IPS` ?** Dans le labo, Kali a une IP privée (donc « interne »). On la déclare comme
connue malveillante, ce qui simule une base de threat intelligence qui l'aurait identifiée.
Pour une vraie IP publique, utilise `ABUSEIPDB_KEY` (optionnel, appel externe : à éviter si ton prof l'interdit).

## 6. Autres scénarios réels dans le labo
| Scénario | Comment le générer | Détection Wazuh |
|---|---|---|
| **Scan de ports** | `nmap -sS -p- IP_VICTIME` depuis Kali | Pas détecté par défaut : nécessite des logs pare-feu (iptables) ou Suricata |
| **Injection SQL web** | Installer Apache + une page vulnérable (DVWA), puis `sqlmap -u "http://IP/page?id=1"` | Règles web (logs Apache) |
| **Modification de fichiers (FIM)** | Sur la victime : `sudo adduser pirate` ou éditer `/etc/passwd` | Module syscheck (FIM) |
| **Phishing** | Pas natif Wazuh : garde les e-mails simulés ou utilise GoPhish | - |

## 7. Pour la section « limites » du rapport
Compare l'alerte **réelle** et l'alerte **simulée** : champs manquants, bruit, volume. Le connecteur
`wazuh_connector.py` est une adaptation minimale : à toi de l'enrichir si tu rencontres d'autres formats.
