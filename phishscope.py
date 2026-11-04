#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  PHISHSCOPE-AI — Console CLI Interactive de Détection de Phishing & OSINT
  Auteur  : Tohon Fourier (CalderaFourier-code)
  Version : 2.0.0 (100% CLI Powerhouse)
  Usage   : python phishscope.py                (Mode Console Interactive)
            python phishscope.py -u <URL>       (Audit rapide d'un lien)
            python phishscope.py -f <FICHIER>   (Audit en lot / Bulk scan)
            python phishscope.py --demo         (Banc d'essai automatisé)
=============================================================================
"""

import argparse
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

# Assure la compatibilité UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# COULEURS & THEME TERMINAL (ANSI)
# =============================================================================
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    LIGHT_GREEN = "\033[38;5;82m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


BANNER = f"""{Colors.CYAN}
  ____  _     _     _     ____                          _    ___ 
 |  _ \\| |__ (_)___| |__ / ___|  ___ ___  _ __   ___   / \\  |_ _|
 | |_) | '_ \\| / __| '_ \\\\___ \\ / __/ _ \\| '_ \\ / _ \\ / _ \\  | | 
 |  __/| | | | \\__ \\ | | |___) | (_| (_) | |_) |  __// ___ \\ | | 
 |_|   |_| |_|_|___/_| |_|____/ \\___\\___/| .__/ \\___/_/   \\_\\___|
                                         |_|                      
  {Colors.LIGHT_GREEN}[ Console CLI d'Analyse Anti-Phishing, OSINT & Homographes ]{Colors.RESET}
  {Colors.GRAY}Auteur : Tohon Fourier | GitHub: CalderaFourier-code | v2.0.0{Colors.RESET}
"""

# =============================================================================
# DICTIONNAIRES & BASES DE CONNAISSANCES THREAT INTEL
# =============================================================================
POPULAR_BRANDS = [
    "google", "microsoft", "apple", "paypal", "netflix", "amazon",
    "facebook", "instagram", "binance", "coinbase", "whatsapp", "telegram",
    "twitter", "chase", "wellsfargo", "bankofamerica", "yahoo", "linkedin",
    "dropbox", "adobe", "spotify", "uber", "steam", "roblox",
    # Marques & Télécoms régionales (Afrique / International)
    "mtn", "moov", "orange", "ecobank", "wave", "societegenerale"
]

SUSPICIOUS_TLDS = {
    ".top": 25, ".xyz": 20, ".club": 15, ".work": 15, ".click": 20,
    ".buzz": 20, ".tk": 25, ".ml": 25, ".ga": 25, ".cf": 25, ".gq": 25,
    ".link": 15, ".stream": 20, ".icu": 20, ".sbs": 20, ".cam": 15,
    ".country": 25, ".loan": 25, ".win": 20, ".racing": 25
}

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "soo.gd", "tiny.cc", "shorte.st", "clck.ru"
]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "security",
    "update", "billing", "confirm", "wallet", "banking", "authenticate",
    "suspended", "urgent", "2fa", "recovery", "password", "support", "secure"
]

CONFUSABLE_CHARS = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0458': 'j', '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p',
    '\u03bd': 'v', '\u0455': 's', '\u04bb': 'h', '\u0501': 'd',
    '\u043c': 'm', '\u0442': 't', '\u0432': 'b', '\u043f': 'n'
}


# =============================================================================
# ALGORITHMES DE DÉTECTION
# =============================================================================
def levenshtein_distance(s1, s2):
    """Calcule la distance d'édition de Levenshtein."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_entropy(s):
    """Calcule l'entropie de Shannon d'une chaîne."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# =============================================================================
# MOTEUR D'ANALYSE PHISHSCOPE
# =============================================================================
class PhishAnalyzer:
    def __init__(self, raw_url):
        self.raw_url = raw_url.strip()
        if not self.raw_url.startswith(("http://", "https://")):
            self.normalized_url = "http://" + self.raw_url
        else:
            self.normalized_url = self.raw_url

        self.parsed = urllib.parse.urlparse(self.normalized_url)
        self.domain = self.parsed.netloc.split(":")[0].lower()
        self.path = self.parsed.path
        self.query = self.parsed.query

        self.findings = []
        self.risk_score = 0
        self.verdict = "INDÉTERMINÉ"
        self.ai_summary = ""
        self.soc_recommendations = []

    def analyze(self):
        self.check_homographs()
        self.check_typosquatting()
        self.check_shortener()
        self.check_heuristics()
        self.check_keywords()
        self.finalize_verdict()
        return self.to_dict()

    def check_homographs(self):
        is_punycode = False
        detected_confusables = []

        try:
            encoded = self.domain.encode("idna").decode("ascii")
            if "xn--" in encoded or "xn--" in self.domain:
                is_punycode = True
        except Exception:
            is_punycode = True

        for char in self.domain:
            if char in CONFUSABLE_CHARS:
                detected_confusables.append(f"'{char}' (substitut de '{CONFUSABLE_CHARS[char]}')")

        if is_punycode or detected_confusables:
            pts = 40
            self.risk_score += pts
            self.findings.append({
                "category": "Homographe / Punycode",
                "severity": "CRITICAL",
                "points": pts,
                "title": "Attaque Homographe Détectée (IDN Spoofing)",
                "description": f"Domaine utilisant des caractères substitués ou un codage Punycode ({self.domain}). Caractères : {', '.join(detected_confusables) if detected_confusables else 'Préfixe xn--'}. Utilisé pour tromper visuellement la victime sur l'identité du site."
            })

    def check_typosquatting(self):
        domain_labels = self.domain.split(".")
        main_label = domain_labels[-2] if len(domain_labels) >= 2 else self.domain
        tokens = re.split(r"[-_0-9]", main_label)
        tokens = [t for t in tokens if len(t) >= 3]

        matched_brand = None
        technique = None

        for brand in POPULAR_BRANDS:
            candidates = [main_label] + tokens
            for cand in candidates:
                dist = levenshtein_distance(cand, brand)
                if dist == 1 and cand != brand:
                    matched_brand = brand
                    technique = f"Typosquatting sur '{cand}' (omission/substitution de 1 lettre vs '{brand}')"
                    break
                elif dist == 2 and len(brand) >= 6 and cand != brand:
                    matched_brand = brand
                    technique = f"Typosquatting sur '{cand}' (distance de 2 vs '{brand}')"
                    break
            if matched_brand:
                break

            if brand in self.domain:
                for kw in ["secure", "security", "login", "verify", "update", "account", "support", "auth", "billing"]:
                    if kw in self.domain:
                        matched_brand = brand
                        technique = f"Combosquatting (combinaison de '{brand}' avec le terme suspect '{kw}')"
                        break
                if matched_brand:
                    break

        if matched_brand:
            pts = 35
            self.risk_score += pts
            self.findings.append({
                "category": "Typosquatting & Usurpation",
                "severity": "CRITICAL",
                "points": pts,
                "title": f"Usurpation de la marque '{matched_brand.upper()}'",
                "description": f"Le domaine tente d'imiter la marque {matched_brand}. Technique : {technique}."
            })

    def check_shortener(self):
        for short in SHORTENER_DOMAINS:
            if short in self.domain:
                pts = 15
                self.risk_score += pts
                self.findings.append({
                    "category": "Masquage de Destination",
                    "severity": "MEDIUM",
                    "points": pts,
                    "title": "URL Raccourcie (Redirection Inconnue)",
                    "description": f"L'URL passe par le réducteur '{short}' pour cacher sa destination réelle et contourner les filtres anti-spam."
                })
                break

    def check_heuristics(self):
        ip_pattern = r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
        if re.match(ip_pattern, self.domain):
            pts = 30
            self.risk_score += pts
            self.findings.append({
                "category": "Structure d'Hôte",
                "severity": "HIGH",
                "points": pts,
                "title": "Adresse IP Numérique Directe",
                "description": "L'URL utilise une adresse IP brute au lieu d'un nom de domaine qualifié (FQDN). Révèle une infrastructure temporaire ou non légitime."
            })

        for tld, pts in SUSPICIOUS_TLDS.items():
            if self.domain.endswith(tld):
                self.risk_score += pts
                self.findings.append({
                    "category": "Réputation TLD",
                    "severity": "MEDIUM",
                    "points": pts,
                    "title": f"TLD à Risque d'Abus ({tld})",
                    "description": f"L'extension '{tld}' est massivement surreprésentée dans les campagnes de spam et d'hameçonnage."
                })
                break

        dot_count = self.domain.count(".")
        if dot_count >= 3 and not re.match(ip_pattern, self.domain):
            pts = 15
            self.risk_score += pts
            self.findings.append({
                "category": "Structure d'Hôte",
                "severity": "MEDIUM",
                "points": pts,
                "title": f"Sous-domaines Multiples ({dot_count} niveaux)",
                "description": "Dissimulation de l'identité du serveur par empilement de sous-domaines pour tromper l'affichage sur mobile."
            })

        main_part = self.domain.split(".")[0]
        entropy = calculate_entropy(main_part)
        if entropy >= 3.75 and len(main_part) >= 10:
            pts = 15
            self.risk_score += pts
            self.findings.append({
                "category": "Heuristique DGA",
                "severity": "MEDIUM",
                "points": pts,
                "title": f"Entropie de Caractères Élevée ({entropy:.2f})",
                "description": "Nom de domaine aléatoire typique des générateurs DGA ou d'empreintes de serveurs éphémères."
            })

        if "@" in self.normalized_url:
            pts = 35
            self.risk_score += pts
            self.findings.append({
                "category": "Obfuscation",
                "severity": "CRITICAL",
                "points": pts,
                "title": "Attaque par Syntaxe d'Authentification (@)",
                "description": "L'URL utilise le séparateur '@' pour masquer visuellement la destination finale."
            })

    def check_keywords(self):
        full_str = (self.path + "?" + self.query + " " + self.domain).lower()
        found = [kw for kw in PHISHING_KEYWORDS if kw in full_str]
        if found:
            pts = min(20, len(found) * 5)
            self.risk_score += pts
            self.findings.append({
                "category": "Ingénierie Sociale",
                "severity": "HIGH" if pts >= 15 else "MEDIUM",
                "points": pts,
                "title": "Mots-clés de Capture d'Identifiants",
                "description": f"Mots suspects identifiés : {', '.join(found[:5])}. Indique une tentative d'hameçonnage de compte ou de coordonnées bancaires."
            })

    def finalize_verdict(self):
        self.risk_score = min(100, self.risk_score)

        if self.risk_score >= 80:
            self.verdict = "CRITIQUE (Phishing Confirmé)"
            verdict_badge = "CRITIQUE"
        elif self.risk_score >= 50:
            self.verdict = "ÉLEVÉ (Probable Hameçonnage)"
            verdict_badge = "ÉLEVÉ"
        elif self.risk_score >= 25:
            self.verdict = "SUSPECT (Vigilance Requise)"
            verdict_badge = "SUSPECT"
        else:
            self.verdict = "FAIBLE (Domaine Légitime / Sans Anomalie)"
            verdict_badge = "LÉGITIME"

        if self.risk_score >= 50:
            critical_points = [f["title"] for f in self.findings if f["severity"] in ["CRITICAL", "HIGH"]]
            summary_reasons = " et ".join(critical_points[:2]) if critical_points else "un cumul d'anomalies structurelles"
            self.ai_summary = (
                f"Menace qualifiée au niveau {verdict_badge} (Score de Risque : {self.risk_score}/100). "
                f"L'analyse a identifié {summary_reasons}. "
                "L'infrastructure est conçue pour détourner des accès ou voler des identifiants d'utilisateurs."
            )
            self.soc_recommendations = [
                "Bloquer l'accès à ce domaine sur les résolveurs DNS (Sinkholing) et proxy.",
                "Rechercher dans les journaux réseau les postes internes ayant contacté cette URL.",
                "En cas de saisie d'identifiants par un agent, réinitialiser immédiatement son mot de passe et révoquer ses sessions.",
                "Ajouter l'indicateur (IoC) à la liste de surveillance du SIEM."
            ]
        else:
            self.ai_summary = (
                f"Score de risque faible ({self.risk_score}/100). "
                "Aucun indicateur de typosquatting, d'attaque homographe ou d'obfuscation critique n'a été détecté."
            )
            self.soc_recommendations = [
                "Aucune mesure de blocage requise.",
                "Maintenir la vigilance habituelle lors de la saisie d'informations sensibles."
            ]

    def to_dict(self):
        return {
            "target_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "ai_executive_summary": self.ai_summary,
            "soc_recommendations": self.soc_recommendations,
            "scan_timestamp": datetime.now().isoformat()
        }


# =============================================================================
# FORMATTAGE & AFFICHAGE TERMINAL ULTRA-PROPRE
# =============================================================================
def render_ascii_gauge(score):
    """Génère une jauge graphique en caractères ASCII/Unicode colorés."""
    total_blocks = 25
    filled = int((score / 100) * total_blocks)
    empty = total_blocks - filled

    if score >= 80:
        col = Colors.RED
        tag = "CRITIQUE (PHISHING CONFIRMÉ)"
    elif score >= 50:
        col = Colors.ORANGE
        tag = "ÉLEVÉ (PROBABLE HAMEÇONNAGE)"
    elif score >= 25:
        col = Colors.YELLOW
        tag = "SUSPECT (VIGILANCE REQUISE)"
    else:
        col = Colors.GREEN
        tag = "FAIBLE (LÉGITIME)"

    bar = f"{col}[{'█' * filled}{'░' * empty}] {score}/100{Colors.RESET} — {col}{Colors.BOLD}{tag}{Colors.RESET}"
    return bar


def display_cli_report(res):
    """Affiche un rapport soigné avec bordures de console professionnelles."""
    score = res["risk_score"]
    col = Colors.RED if score >= 80 else Colors.ORANGE if score >= 50 else Colors.YELLOW if score >= 25 else Colors.GREEN

    print("\n" + f"{Colors.CYAN}┌" + "─" * 88 + "┐" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}{Colors.WHITE}RAPPORT D'ANALYSE FORENSIQUE PHISHSCOPE-AI{Colors.RESET}{' ' * 45}{Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}├" + "─" * 88 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Cible inspectée : {Colors.BOLD}{res['normalized_url'][:65]}{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Domaine extrait : {Colors.CYAN}{res['domain']}{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Horodatage      : {res['scan_timestamp'][:19]}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Niveau Risque   : {render_ascii_gauge(score)}")
    print(f"{Colors.CYAN}├" + "─" * 88 + "┤" + f"{Colors.RESET}")

    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}SYNTHÈSE DE L'INTELLIGENCE :{Colors.RESET}")
    words = res['ai_executive_summary'].split()
    line = "  "
    for w in words:
        if len(line) + len(w) + 1 > 84:
            print(f"{Colors.CYAN}│{Colors.RESET} {line}")
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        print(f"{Colors.CYAN}│{Colors.RESET} {line}")

    print(f"{Colors.CYAN}├" + "─" * 88 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}INDICATEURS OSINT & ANOMALIES IDENTIFIÉES ({res['findings_count']}) :{Colors.RESET}")

    if not res["findings"]:
        print(f"{Colors.CYAN}│{Colors.RESET}  {Colors.GREEN}[✓] Aucun indicateur de malveillance détecté sur cette cible.{Colors.RESET}")
    else:
        for f in res["findings"]:
            s_col = Colors.RED if f['severity'] == "CRITICAL" else Colors.ORANGE if f['severity'] == "HIGH" else Colors.YELLOW
            print(f"{Colors.CYAN}│{Colors.RESET}   {s_col}▶ [{f['severity']} +{f['points']}pts]{Colors.RESET} {Colors.BOLD}{f['title']}{Colors.RESET} ({f['category']})")
            print(f"{Colors.CYAN}│{Colors.RESET}     {Colors.GRAY}↳ {f['description'][:80]}{Colors.RESET}")

    print(f"{Colors.CYAN}├" + "─" * 88 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}RECOMMANDATIONS OPÉRATIONNELLES SOC :{Colors.RESET}")
    for r in res["soc_recommendations"]:
        print(f"{Colors.CYAN}│{Colors.RESET}  {Colors.YELLOW}⚡{Colors.RESET} {r}")

    print(f"{Colors.CYAN}└" + "─" * 88 + "┘" + f"{Colors.RESET}\n")


# =============================================================================
# CONSOLE INTERACTIVE (CLI SHELL)
# =============================================================================
def interactive_console():
    """Démarre une session shell interactive dédiée dans le terminal."""
    print(f"{Colors.LIGHT_GREEN}Session interactive démarrée.{Colors.RESET} Tapez une URL ou une commande ({Colors.CYAN}help{Colors.RESET} pour la liste).\n")

    history = []

    while True:
        try:
            prompt = f"{Colors.GREEN}phishscope{Colors.RESET}@{Colors.CYAN}fourier{Colors.RESET}> "
            user_input = input(prompt).strip()

            if not user_input:
                continue

            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd in ["exit", "quit", "q"]:
                print(f"\n{Colors.YELLOW}[*] Fermeture de la console PhishScope-AI. Au revoir.{Colors.RESET}")
                break

            elif cmd in ["clear", "cls"]:
                os.system("cls" if os.name == "nt" else "clear")
                print(BANNER)

            elif cmd in ["help", "?"]:
                print(f"\n{Colors.BOLD}Commandes disponibles dans la console :{Colors.RESET}")
                print(f"  {Colors.CYAN}<URL>{Colors.RESET}            : Collez directement n'importe quelle URL pour l'analyser")
                print(f"  {Colors.CYAN}scan <URL>{Colors.RESET}       : Analyse l'URL spécifiée")
                print(f"  {Colors.CYAN}bulk <fichier>{Colors.RESET}   : Scanne une liste d'URLs depuis un fichier texte (1 URL par ligne)")
                print(f"  {Colors.CYAN}demo{Colors.RESET}             : Lance la suite de démonstration automatisée")
                print(f"  {Colors.CYAN}history{Colors.RESET}          : Affiche les scans réalisés durant la session")
                print(f"  {Colors.CYAN}export <json>{Colors.RESET}    : Exporte l'historique de la session dans un fichier JSON")
                print(f"  {Colors.CYAN}clear{Colors.RESET}            : Efface l'écran du terminal")
                print(f"  {Colors.CYAN}exit{Colors.RESET}             : Quitte la console\n")

            elif cmd == "demo":
                run_demo()

            elif cmd == "history":
                if not history:
                    print(f"{Colors.GRAY}[i] Aucun scan dans l'historique de cette session.{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.BOLD}Historique des scans ({len(history)}) :{Colors.RESET}")
                    for idx, h in enumerate(history, 1):
                        col = Colors.RED if h['risk_score'] >= 80 else Colors.ORANGE if h['risk_score'] >= 50 else Colors.YELLOW if h['risk_score'] >= 25 else Colors.GREEN
                        print(f"  {idx}. {h['domain']:<30} -> {col}{h['risk_score']}/100 ({h['verdict'].split()[0]}){Colors.RESET}")
                    print()

            elif cmd == "export":
                out_name = parts[1] if len(parts) > 1 else "phishscope_history.json"
                with open(out_name, "w", encoding="utf-8") as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
                print(f"{Colors.GREEN}[✓] Historique exporté ({len(history)} entrées) dans :{Colors.RESET} {out_name}\n")

            elif cmd == "bulk":
                if len(parts) < 2:
                    print(f"{Colors.RED}[!] Usage : bulk <chemin_du_fichier.txt>{Colors.RESET}\n")
                    continue
                filepath = parts[1]
                run_bulk_scan(filepath)

            elif cmd == "scan":
                if len(parts) < 2:
                    print(f"{Colors.RED}[!] Usage : scan <URL>{Colors.RESET}\n")
                    continue
                target = parts[1]
                analyzer = PhishAnalyzer(target)
                res = analyzer.analyze()
                history.append(res)
                display_cli_report(res)

            else:
                # Si l'utilisateur colle directement une URL
                target = user_input
                analyzer = PhishAnalyzer(target)
                res = analyzer.analyze()
                history.append(res)
                display_cli_report(res)

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] Interruption détectée. Tapez 'exit' pour quitter.{Colors.RESET}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur d'analyse : {e}{Colors.RESET}\n")


# =============================================================================
# BULK SCAN (ANALYSE EN LOT)
# =============================================================================
def run_bulk_scan(filepath):
    """Analyse un fichier contenant une liste d'URLs (une par ligne)."""
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Fichier introuvable :{Colors.RESET} {filepath}\n")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"\n{Colors.CYAN}[*] Début de l'audit en lot : {len(urls)} URLs à analyser dans '{filepath}'...{Colors.RESET}\n")
    print(f"{Colors.BOLD}{'#':<4} {'DOMAINE CIBLE':<35} {'SCORE':<10} {'VERDICT':<30}{Colors.RESET}")
    print("-" * 85)

    crit_count = 0
    for idx, u in enumerate(urls, 1):
        analyzer = PhishAnalyzer(u)
        res = analyzer.analyze()
        score = res["risk_score"]
        col = Colors.RED if score >= 80 else Colors.ORANGE if score >= 50 else Colors.YELLOW if score >= 25 else Colors.GREEN

        if score >= 50:
            crit_count += 1

        print(f"{idx:<4} {res['domain'][:33]:<35} {col}{score}/100{Colors.RESET:<5} {col}{res['verdict']}{Colors.RESET}")

    print("-" * 85)
    print(f"Synthèse : {Colors.BOLD}{len(urls)} liens audités{Colors.RESET} | {Colors.RED}{crit_count} menace(s) potentielle(s){Colors.RESET}\n")


# =============================================================================
# BANC D'ESSAI AUTOMATISÉ (DEMO)
# =============================================================================
def run_demo():
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}=== BANC D'ESSAI AUTOMATISÉ PHISHSCOPE-AI ==={Colors.RESET}\n")

    test_cases = [
        ("https://paypa1-update-security.top/login.php", "Typosquatting PayPal + TLD Abusif + Mots-clés de Phishing"),
        ("http://аpple.com/verify-account", "Attaque Homographe Cyrillique (аpple) + Usurpation Apple"),
        ("http://bit.ly/3x8fQZ", "Redirection masquée par réducteur d'URL"),
        ("https://www.google.com", "Domaine officiel légitime")
    ]

    for u, scenario in test_cases:
        print(f"{Colors.GRAY}Scénario de test : {scenario}{Colors.RESET}")
        time.sleep(0.3)
        analyzer = PhishAnalyzer(u)
        res = analyzer.analyze()
        display_cli_report(res)

    print(f"{Colors.LIGHT_GREEN}[✓] Démonstration achevée avec succès !{Colors.RESET}\n")


# =============================================================================
# POINT D'ENTRÉE DU SCRIPT
# =============================================================================
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="PhishScope-AI : Console CLI d'Analyse Anti-Phishing, OSINT & Homographes",
        epilog="Exemples :\n  python phishscope.py                                 (Console interactive)\n  python phishscope.py -u https://paypa1-security.top  (Audit direct)\n  python phishscope.py -f urls.txt                     (Audit en lot)\n  python phishscope.py --demo                          (Banc d'essai)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="URL suspecte à inspecter immédiatement")
    parser.add_argument("-f", "--file", help="Fichier texte contenant une liste d'URLs à auditer en lot")
    parser.add_argument("-i", "--interactive", action="store_true", help="Ouvre la console interactive PhishScope")
    parser.add_argument("--demo", action="store_true", help="Lance la démonstration des différents vecteurs d'attaque")
    parser.add_argument("--json", action="store_true", help="Sortie au format JSON brut pour scripts et pipelines")

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.file:
        run_bulk_scan(args.file)
        return

    if args.url:
        analyzer = PhishAnalyzer(args.url)
        res = analyzer.analyze()
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            display_cli_report(res)
        return

    # Par défaut : Console Interactive dans le terminal
    interactive_console()


if __name__ == "__main__":
    main()
