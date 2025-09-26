# scanner-vulnerabilites-basique
Outil éducatif en Python pour scanner une cible (IP/domaine) : détection de ports ouverts, identification basique de services HTTP. À n’utiliser que sur des cibles autorisées.

/opt/homebrew/bin/python3 -m venv .venv                                                      
source .venv/bin/activate

.venv/bin/python PortScanner.py scanme.nmap.org -p 1-1024 -o nmap_scan.json --format json

.venv/bin/python PortScanner.py scanme.nmap.org -p 1-1024 -o results.csv --format csv