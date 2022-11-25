# TP3 Système de détection d'intrusions - PUC Hugo

## Partie 1

### Exercice 1

Les NIDS ou Network Intrusion Detection System sont des sondes réseaux pour analyser le trafic et essayer de trouver des activités inhabituelles, comme le scanning, les tentatives d’intrusion, les mouvements latéraux, l’exfiltration, les portes dérobées, etc.
Au départ, cela se faisait par le biais de signatures et ces solutions ont parfois évolué vers le NTA. TEHTRIS NTA comprend des fonctionnalités NIDS avec plus de 50 000 règles régulièrement mises à jour. 

### Exercice 2

requête -> GET /XXX HTTP/1.1
réponse -> HTTP/1.1 200 OK

### Exercice 3

Au début du paquet IP, donc HTTP/1.0
77 77 77 -> www

### Exercice 10

sudo apt install -y libpcap-dev
gcc main.c -o main -lpcap
