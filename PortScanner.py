"""
Scanner de Ports Basique
Auteur: Laetitia Tiberghien
Description: Scan simple de ports avec multithreading
"""

import csv
import json
import logging
import socket
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class PortScanner :

    def __init__(self, target,threads=10, timeout=2):
        self.target = target    # IP ou domaine
        self.threads = threads  # nombre de threads paralèles
        self.timeout = timeout  # temps d'attente par connexion
        self.open_ports = []    # liste des ports ouverts trouvés

    def resolve_target(self):
        """Résout le nom d'hôte en adresse IP"""
        try:
            # verifie si c'est une IP (que des chiffres et points)
            if not self.target.replace('.', '').isdigit():
                # si pas une IP on résout le nom de domaine
                ip = socket.gethostbyname(self.target)
                print(f"[+] {self.target} résolu en {ip}")
                return ip
            return self.target
        except socket.gaierror:
            print(f"[-] Impossible de résoudre {self.target}")
            return None
        
    def scan_port(self, port):
        """Scan un port individuel"""
        try:
            # crée un socket TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                # connect_ex retourne 0 si succès sinon erreur
                if result == 0:
                    service = self.get_service_name(port)
                    return port, service, "ouvert"
                return port, None, "fermé"
        except Exception as e:
            return port, None, f"erreur: {str(e)}"
    
    def get_service_name(self, port):
        """Tente d'identifier le service sur un port"""
        try:
            # tente de recuperer le service standard
            service = socket.getservbyport(port)
            return service
        except:
            # bdd de services communs si non trouvé
            common_services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
                443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
                3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP'
            }
            return common_services.get(port, 'Inconnu')
        
    def port_scan(self, port_range="1-1024"):
        """Scan une plage de ports"""
        print(f"[*] Scan des ports {port_range} sur {self.target}")

        # convertit "1-100" en range(1, 101)
        start_port, end_port = map(int, port_range.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
        
        # ThreadPoolExecutor gère les threads automatiquement
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # création d'un dictionnaire {future: port} pour tous les ports
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in ports_to_scan
            }
            
            # parcourt des résultats au fur et a mesure qu'ils arrivent
            for future in as_completed(future_to_port):
                port, service, status = future.result()
                if status == "ouvert":
                    print(f"[+] Port {port} ouvert - {service}")
                    self.open_ports.append((port, service))

    def save_results(self, filename: str = None, fmt: str = "json"):
        if not filename:
            return
        fmt = fmt.lower()
        if fmt == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.open_ports, f, ensure_ascii=False, indent=2)
            logging.info(f"Résultats sauvegardés en JSON -> {filename}")
        elif fmt == "csv":
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["port", "service", "banner"])
                writer.writeheader()
                for r in self.open_ports:
                    # si r est un tuple (port, service) -> convertir
                    if isinstance(r, tuple):
                        port, service = r[0], r[1] if len(r) > 1 else None
                        row = {"port": port, "service": service, "banner": ""}
                    elif isinstance(r, dict):
                        # assurez-vous que les clés existent
                        row = {"port": r.get("port"), "service": r.get("service"), "banner": r.get("banner", "")}
                    else:
                        # fallback générique
                        row = {"port": None, "service": str(r), "banner": ""}
                    writer.writerow(row)
            logging.info(f"Résultats sauvegardés en CSV -> {filename}")
        else:
            logging.warning("Format inconnu pour la sauvegarde. Utilise json/csv.")

def main():
    parser = argparse.ArgumentParser(description="Scanner de Ports Basique")
    parser.add_argument("target", help="IP ou domaine à scanner")
    parser.add_argument("-p", "--ports", default="1-1024", help="Plage de ports à scanner")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Nombre de threads")
    parser.add_argument("--timeout", type=float, default=2, help="Timeout par connexion (défaut: 2s)")
    parser.add_argument("-o", "--output", help="Fichier de sortie (ex: results.json ou results.csv)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Format de sortie")
    

    
    args = parser.parse_args()
    
    print(f"[*] Démarrage du scan sur {args.target}")
    start_time = datetime.now()
    
    scanner = PortScanner(args.target, args.threads, args.timeout)
    
    resolved_target = scanner.resolve_target()
    if not resolved_target:
        return
    
    scanner.target = resolved_target # utilise l'IP résolue
    
    # scan des ports
    scanner.port_scan(args.ports)
    
    # calcul et affichage du temps écoulé
    elapsed_time = datetime.now() - start_time
    print(f"\n[o] Scan terminé en {elapsed_time.total_seconds():.2f} secondes")
    print(f"[+] {len(scanner.open_ports)} ports ouverts trouvés")

    # sauvegarde des résultats si demandé
    if args.output:
        scanner.save_results(args.output, fmt=args.format)


if __name__ == "__main__":
    main()