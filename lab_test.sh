#!/bin/bash
cd ~/soc-agent
source .venv/bin/activate

# 1. Relancer les services (WSL ne le fait pas seul)
sudo service rsyslog start
sudo service ssh start
sudo /var/ossec/bin/wazuh-control start
sudo /var/ossec/bin/wazuh-control status

# 2. IP actuelle de WSL (peut changer à chaque redémarrage)
IP=$(hostname -I | awk '{print $1}')
echo "IP du labo : $IP"

# 3. Repartir d'un fichier d'alertes propre (labo uniquement)
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json

# 4. Attaque brute force réelle sur ta propre machine
hydra -l testuser -P ~/mini.txt ssh://$IP -t 4
sleep 5

# 5. Récupérer, convertir, analyser
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_wazuh.json
sudo chown $USER ~/alerts_wazuh.json
python wazuh_connector.py --file ~/alerts_wazuh.json --out data/wazuh_alerts.json
EXTRA_BAD_IPS=$IP python analyze_file.py data/wazuh_alerts.json --backend ${1:-mock}