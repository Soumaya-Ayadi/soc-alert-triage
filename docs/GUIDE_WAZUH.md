# Guide : Wazuh léger sous WSL + vraie alerte brute force SSH (sans VirtualBox, sans Kali)

> Labo 100 % local sur ta propre machine. N'attaque jamais une machine qui ne t'appartient pas.
> Ce guide n'a pas été testé de bout en bout par l'auteur : vérifie les commandes sur documentation.wazuh.com si une étape échoue.

## 0. Principe et budget mémoire
Wazuh complet (indexeur + dashboard) est gourmand. Notre agent IA n'a besoin que du **manager** Wazuh,
qui écrit les alertes dans `/var/ossec/logs/alerts/alerts.json` (~1 à 1,5 Go de RAM). Pas de dashboard, pas de VM.

| Composant | RAM approx. |
|---|---|
| WSL2 + Wazuh manager + SSH + Hydra | 2 à 3 Go |
| Ollama + modèle 3B (`llama3.2:3b`) | 3 à 4 Go |
| Windows + navigateur | 4 à 5 Go |

Limite WSL pour éviter qu'il avale toute la RAM : crée `C:\Users\TON_NOM\.wslconfig` :
```
[wsl2]
memory=5GB
processors=4
```
puis `wsl --shutdown` dans PowerShell et relance Ubuntu.
Astuce : fais tourner Ollama côté Windows et le projet Python côté WSL (ou tout dans WSL si tu préfères).

## 1. Installer le manager Wazuh (dans Ubuntu WSL)
```bash
sudo apt update && sudo apt install -y curl gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-manager
sudo /var/ossec/bin/wazuh-control start
sudo /var/ossec/bin/wazuh-control status      # analysisd et remoted doivent être "running"
```
Le manager surveille aussi la machine locale : **pas besoin de machine victime séparée**.
(Si `systemctl` ne marche pas, c'est que WSL n'a pas systemd : utilise `wazuh-control`, comme ci-dessus.)

## 2. Préparer la « victime » : le serveur SSH local
```bash
sudo apt install -y openssh-server rsyslog hydra
sudo adduser testuser                 # mot de passe simple, ex. : password123
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo service rsyslog start && sudo service ssh start
ls /var/log/auth.log                  # doit exister : c'est le fichier que Wazuh lit
```
Pour que Wazuh lise ce fichier, vérifie que `/var/ossec/etc/ossec.conf` contient une section `<localfile>`
pour `/var/log/auth.log` (présente par défaut sur Debian/Ubuntu dans la plupart des versions). Sinon ajoute :
```xml
<localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
```
puis `sudo /var/ossec/bin/wazuh-control restart`.

## 3. Générer la vraie attaque (depuis ta propre machine)
Pas besoin de Kali : Hydra est installé via `apt`.
```bash
printf "%s\n" password1 azerty 123456 qwerty admin letmein welcome monkey dragon master \
  iloveyou sunshine princess football abc123 login starwars hello freedom shadow > mini.txt
IP=$(hostname -I | awk '{print $1}')
hydra -l testuser -P mini.txt ssh://$IP -t 4
sudo tail -f /var/ossec/logs/alerts/alerts.json      # les alertes apparaissent ici
```
Cible l'IP de la machine plutôt que `127.0.0.1` : le localhost est parfois traité à part par Wazuh.
Tu dois voir des échecs d'authentification (règle 5760, niveau 5) puis une alerte de brute force
(règle 5763, niveau 10). **Les numéros de règles peuvent varier : repère les tiens dans le fichier.**
Si rien n'apparaît : `sudo tail /var/ossec/logs/ossec.log` (erreurs du manager) et vérifie que `/var/log/auth.log` se remplit.

## 4. Passer l'alerte à l'agent IA
```bash
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_wazuh.json && sudo chown $USER ~/alerts_wazuh.json
cd ~/soc-agent
python wazuh_connector.py --file ~/alerts_wazuh.json --out data/wazuh_alerts.json
EXTRA_BAD_IPS=$IP python analyze_file.py data/wazuh_alerts.json            # + --backend ollama pour le vrai LLM
```
**Pourquoi `EXTRA_BAD_IPS` ?** L'attaque vient d'une IP locale (« interne »). On la déclare connue malveillante
pour simuler une base de threat intelligence. C'est à expliquer au jury (voir section 6).

## 5. Autres scénarios réels (optionnels, selon le temps)
| Scénario | Comment | Remarque |
|---|---|---|
| **Modification de fichiers (FIM)** | `sudo adduser pirate` ou éditer `/etc/passwd` | Module syscheck de Wazuh ; la fréquence de scan est configurable (`ossec.conf`) |
| **Injection SQL web** | Apache + page vulnérable (DVWA) + `sqlmap` | Plus lourd à installer : à garder pour plus tard |
| **Scan de ports** | `nmap -sS -p- $IP` | Non détecté par défaut (il faut logs pare-feu ou Suricata) |
| **Phishing** | - | Pas natif Wazuh : reste sur les e-mails simulés |

## 6. Ce qu'il faut dire en soutenance
- « Le manager Wazuh tourne sous WSL ; l'attaque brute force est réelle (Hydra), la détection est faite par les règles Wazuh. »
- « Le connecteur transforme le format Wazuh en preuves pour l'agent. L'IP est déclarée malveillante pour simuler la threat intelligence. »
- Limites : labo mono-machine, un seul scénario réel, le reste est simulé.

## 7. Plan B si ça ne marche pas après 1 à 2 heures
Garde le dataset simulé pour la démo en direct et présente Wazuh comme perspective, ou enregistre l'alerte
réelle dès qu'elle fonctionne une fois et rejoue-la depuis le fichier JSON pendant la soutenance.