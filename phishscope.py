#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
  PHISHSCOPE-AI v3.0 — Console CLI Forensique de Détection de Phishing & OSINT
  Auteur  : Tohon Fourier (CalderaFourier-code)
  Version : 3.0.0 (Enterprise SOC Edition)
  Moteur  : Détection d'Homoglyphes, Typosquatting, Usurpation de Marque,
            Résolution DNS, Déroulage de Redirections, Inspection SSL/TLS,
            Âge du Domaine (RDAP), Threat Intel (VirusTotal / SafeBrowsing)
=============================================================================
"""

import argparse
import base64
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Compatibilité encodage UTF-8 sous Windows PowerShell / CMD
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# COULEURS ANSI & THEME CYBER
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
  {Colors.LIGHT_GREEN}[ Moteur OSINT Anti-Phishing, Détection d'Homographes & Threat Intel v3.0 ]{Colors.RESET}
  {Colors.GRAY}Auteur : Tohon Fourier | GitHub: CalderaFourier-code | SOC Enterprise Edition{Colors.RESET}
"""


# =============================================================================
# BASE DE CONNAISSANCES : MARQUES & DOMAINES OFFICIELS CERTIFIÉS
# =============================================================================
OFFICIAL_BRANDS = {
    "google": [
        "google.com", "google.fr", "google.bj", "google.co.uk", "youtube.com",
        "gmail.com", "googleapis.com", "gstatic.com", "googleusercontent.com"
    ],
    "microsoft": [
        "microsoft.com", "office.com", "live.com", "outlook.com", "azure.com",
        "microsoftonline.com", "windows.net", "bing.com", "sharepoint.com"
    ],
    "apple": [
        "apple.com", "icloud.com", "apple-dns.net"
    ],
    "paypal": [
        "paypal.com", "paypal-communication.com", "paypalobjects.com"
    ],
    "amazon": [
        "amazon.com", "amazon.fr", "aws.amazon.com", "media-amazon.com", "amazonaws.com"
    ],
    "netflix": [
        "netflix.com", "nflxext.com", "nflxvideo.net"
    ],
    "facebook": [
        "facebook.com", "fb.com", "messenger.com", "fbcdn.net"
    ],
    "instagram": [
        "instagram.com", "cdninstagram.com"
    ],
    "whatsapp": [
        "whatsapp.com", "whatsapp.net"
    ],
    "telegram": [
        "telegram.org", "t.me"
    ],
    "binance": [
        "binance.com", "binance.cloud"
    ],
    "coinbase": [
        "coinbase.com"
    ],
    "github": [
        "github.com", "github.io", "githubusercontent.com"
    ],
    "linkedin": [
        "linkedin.com", "licdn.com"
    ],
    "twitter": [
        "twitter.com", "x.com", "t.co", "twimg.com"
    ],
    "chase": [
        "chase.com"
    ],
    "wellsfargo": [
        "wellsfargo.com"
    ],
    "bankofamerica": [
        "bankofamerica.com"
    ],
    # Télécoms & Banques d'Afrique de l'Ouest / Régionales
    "orange": [
        "orange.com", "orange.fr", "orange.sn", "orange.ci"
    ],
    "mtn": [
        "mtn.com", "mtn.bj", "mtn.ng", "mtn.ci"
    ],
    "moov": [
        "moov-africa.bj", "moov.africa"
    ],
    "wave": [
        "wave.com"
    ],
    "ecobank": [
        "ecobank.com"
    ],
    "societegenerale": [
        "societegenerale.com", "societegenerale.fr", "sg.com"
    ]
}

# TLDs à haut taux d'abus / faible coût
SUSPICIOUS_TLDS = {
    ".top": 25, ".xyz": 20, ".club": 15, ".work": 15, ".click": 20,
    ".buzz": 20, ".tk": 30, ".ml": 30, ".ga": 30, ".cf": 30, ".gq": 30,
    ".link": 15, ".stream": 20, ".icu": 25, ".sbs": 25, ".cam": 20,
    ".country": 25, ".loan": 25, ".win": 20, ".racing": 25, ".vip": 15,
    ".rest": 20, ".fit": 15, ".casa": 20, ".cfd": 25, ".skin": 20
}

# Réducteurs d'URL connus
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "soo.gd", "tiny.cc", "shorte.st", "clck.ru",
    "rotf.lol", "v.gd"
]

# Plateformes d'hébergement gratuit / sans vérification souvent abusées
FREE_HOSTING_PLATFORMS = [
    "workers.dev", "pages.dev", "web.app", "firebaseapp.com",
    "vercel.app", "netlify.app", "glitch.me", "ngrok-free.app",
    "ngrok.io", "trycloudflare.com", "wixsite.com", "weebly.com"
]

# Mots-clés typiques de pages d'hameçonnage
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "security",
    "update", "billing", "confirm", "wallet", "banking", "authenticate",
    "suspended", "urgent", "2fa", "recovery", "password", "support",
    "secure", "validation", "restore", "securise", "connexion", "compte"
]

# Caractères homoglyphes / confusables (Cyrillique, Grec, etc.)
CONFUSABLE_CHARS = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0458': 'j', '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p',
    '\u03bd': 'v', '\u0455': 's', '\u04bb': 'h', '\u0501': 'd',
    '\u043c': 'm', '\u0442': 't', '\u0432': 'b', '\u043f': 'n',
    '\u0459': 's', '\u0491': 'g'
}


# =============================================================================
# ALGORITHMES LEXICAUX & HEURISTIQUES
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
    """Calcule l'entropie de Shannon pour repérer les domaines DGA aléatoires."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def normalize_leetspeak(s):
    """Normalise les substitutions de caractères (leet speak) pour démasquer l'usurpation."""
    trans = str.maketrans('01358', 'oldeb')
    cleaned = s.lower().replace('vv', 'w').replace('rn', 'm')
    return cleaned.translate(trans)


def extract_registered_domain(hostname):
    """
    Extrait précisément le domaine racine enregistré et les sous-domaines
    en tenant compte des TLDs multi-parties (ex: .co.uk, .com.bj, .com.fr).
    """
    hostname = hostname.lower().strip('.')
    multi_tlds = {
        'co.uk', 'com.fr', 'co.jp', 'gov.fr', 'gouv.fr', 'com.bj', 'edu.bj',
        'com.ng', 'co.za', 'com.au', 'org.uk', 'net.au', 'com.br', 'co.nz'
    }
    parts = hostname.split('.')
    if len(parts) <= 2:
        return hostname, ""

    last_two = '.'.join(parts[-2:])
    if last_two in multi_tlds and len(parts) >= 3:
        registered = '.'.join(parts[-3:])
        subdomain = '.'.join(parts[:-3])
    else:
        registered = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])

    return registered, subdomain


# =============================================================================
# SONDES RÉSEAU OSINT (DNS, RDAP, TLS, REDIRECTIONS)
# =============================================================================
class NetworkOsintProbe:
    """Effectue des investigations actives non-intrusives sur la cible."""

    def __init__(self, timeout=3.0):
        self.timeout = timeout

    def resolve_dns(self, hostname):
        """Résout l'adresse IP et vérifie la présence d'IPs privées/bogus."""
        try:
            ip = socket.gethostbyname(hostname)
            is_private = (
                ip.startswith("10.") or
                ip.startswith("192.168.") or
                ip.startswith("127.") or
                ip.startswith("172.16.") or
                ip == "0.0.0.0"
            )
            return {
                "success": True,
                "ip": ip,
                "is_private": is_private,
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "ip": None,
                "is_private": False,
                "error": str(e)
            }

    def unmask_shortener(self, url):
        """Suit les redirections HTTP (301/302) pour démasquer la destination finale."""
        history = [url]
        current_url = url

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)

        for _ in range(5):
            try:
                req = urllib.request.Request(
                    current_url,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishScope/3.0'}
                )
                with opener.open(req, timeout=self.timeout) as resp:
                    break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get('Location')
                    if loc:
                        loc = urllib.parse.urljoin(current_url, loc)
                        history.append(loc)
                        current_url = loc
                        continue
                break
            except Exception:
                break

        return {
            "initial_url": url,
            "final_url": current_url,
            "redirect_count": len(history) - 1,
            "chain": history
        }

    def inspect_tls(self, hostname, port=443):
        """Inspecte le certificat SSL/TLS (émetteur, validité, SANs)."""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    issuer_name = (
                        issuer_dict.get('organizationName') or
                        issuer_dict.get('commonName') or
                        "Inconnu"
                    )
                    expiry = cert.get('notAfter')
                    san_list = [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']

                    # Détection certificat gratuit / éphémère (Let's Encrypt / cPanel)
                    is_free_cert = any(x in issuer_name.lower() for x in ["let's encrypt", "cpanel", "zerossl"])

                    return {
                        "has_tls": True,
                        "issuer": issuer_name,
                        "expiry": expiry,
                        "is_free_cert": is_free_cert,
                        "san_count": len(san_list),
                        "subject": subject_dict.get('commonName', hostname),
                        "error": None
                    }
        except ssl.SSLError as e:
            return {"has_tls": False, "issuer": None, "error": f"Erreur SSL : {e}"}
        except Exception as e:
            return {"has_tls": False, "issuer": None, "error": f"Non joignable en HTTPS ({e})"}

    def query_rdap_age(self, registered_domain):
        """Interroge l'API standardisée ICANN RDAP pour déterminer l'âge du domaine."""
        try:
            url = f"https://rdap.org/domain/{registered_domain}"
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'PhishScope-AI/3.0'}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                creation_date_str = None
                for ev in data.get('events', []):
                    if ev.get('eventAction') == 'registration':
                        creation_date_str = ev.get('eventDate')
                        break

                if creation_date_str:
                    clean_str = creation_date_str.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_str)
                    now = datetime.now(dt.tzinfo or timezone.utc)
                    age_days = (now - dt).days

                    registrar = "Non spécifié"
                    for entity in data.get('entities', []):
                        if 'registrar' in entity.get('roles', []):
                            vcard = entity.get('vcardArray', [])
                            if len(vcard) > 1:
                                for prop in vcard[1]:
                                    if prop[0] == 'fn':
                                        registrar = prop[3]
                                        break

                    return {
                        "success": True,
                        "creation_date": creation_date_str[:10],
                        "age_days": age_days,
                        "registrar": registrar,
                        "is_brand_new": age_days <= 30
                    }
        except Exception:
            pass

        return {
            "success": False,
            "creation_date": None,
            "age_days": None,
            "registrar": None,
            "is_brand_new": False
        }

    def query_virustotal(self, target_url, domain):
        """Interroge l'API VirusTotal v3 si une clé d'API est configurée."""
        api_key = os.environ.get("VT_API_KEY", "").strip()
        if not api_key:
            return {
                "configured": False,
                "malicious_count": 0,
                "total_engines": 0,
                "reputation": 0,
                "message": "Clé VT_API_KEY non configurée (mode heuristique local)"
            }

        try:
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            req = urllib.request.Request(
                endpoint,
                headers={"x-apikey": api_key, "User-Agent": "PhishScope-AI/3.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
                stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values())
                return {
                    "configured": True,
                    "malicious_count": malicious + suspicious,
                    "total_engines": total,
                    "reputation": payload.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "message": f"{malicious} moteur(s) antivirus ont classé l'URL comme malveillante sur {total}"
                }
        except Exception as e:
            return {
                "configured": True,
                "malicious_count": 0,
                "total_engines": 0,
                "reputation": 0,
                "message": f"Erreur de requête VirusTotal : {e}"
            }


# =============================================================================
# MOTEUR D'ANALYSE PRINCIPAL : PHISHSCOPE ANALYZER
# =============================================================================
class PhishAnalyzer:
    def __init__(self, raw_url, enable_network=True):
        self.raw_url = raw_url.strip()
        if not self.raw_url.startswith(("http://", "https://")):
            self.normalized_url = "http://" + self.raw_url
        else:
            self.normalized_url = self.raw_url

        self.enable_network = enable_network
        self.probe = NetworkOsintProbe(timeout=2.5)

        self.parsed = urllib.parse.urlparse(self.normalized_url)
        self.hostname = self.parsed.netloc.split(":")[0].lower()
        self.path = self.parsed.path
        self.query = self.parsed.query

        self.registered_domain, self.subdomains = extract_registered_domain(self.hostname)

        # Résultats
        self.findings = []
        self.risk_score = 0
        self.verdict = "INDÉTERMINÉ"
        self.verdict_class = "UNKNOWN"
        self.ai_summary = ""
        self.soc_recommendations = []

        # Télémétrie OSINT
        self.osint_data = {
            "resolved_ip": None,
            "ip_is_private": False,
            "redirect_unmasked": False,
            "final_destination": self.normalized_url,
            "domain_age_days": None,
            "domain_created": None,
            "registrar": None,
            "tls_issuer": None,
            "tls_is_free": False,
            "vt_stats": None,
            "is_official_brand_domain": False,
            "matched_official_brand": None
        }

    def analyze(self):
        # 1. Vérification d'authenticité légitime (Whitelist / Domaines Certifiés)
        self.check_brand_authenticity()

        # Si le domaine est 100% officiel et authentique, on l'évalue sans fausse alerte
        if self.osint_data["is_official_brand_domain"]:
            if self.enable_network:
                self.run_network_probes()
            self.check_legitimate_brand_safety()
            self.finalize_verdict()
            return self.to_dict()

        # 2. Détection d'Attaques Homographes & Punycode
        self.check_homographs()

        # 3. Détection de Typosquatting & Usurpation par Sous-domaine
        self.check_brand_impersonation()

        # 4. Détection d'Abus de Plateformes Cloud Gratuites
        self.check_free_hosting_abuse()

        # 5. Détection de Réducteurs d'URLs
        self.check_shortener()

        # 6. Sondes Réseau Actives (DNS, RDAP, Redirection, SSL)
        if self.enable_network:
            self.run_network_probes()

        # 7. Heuristiques Structurelles & Obfuscation
        self.check_heuristics()

        # 8. Mots-clés de Capture d'Identifiants
        self.check_keywords()

        # 9. Synthèse Finale & Recommandations SOC
        self.finalize_verdict()
        return self.to_dict()

    def check_brand_authenticity(self):
        """Vérifie si le domaine appartient réellement et officiellement à la marque."""
        for brand, domains in OFFICIAL_BRANDS.items():
            if self.registered_domain in domains:
                self.osint_data["is_official_brand_domain"] = True
                self.osint_data["matched_official_brand"] = brand.upper()
                break

    def check_legitimate_brand_safety(self):
        """Traite les domaines authentiques (ex: accounts.google.com, login.live.com)."""
        brand = self.osint_data["matched_official_brand"]
        self.risk_score = 0
        self.verdict = f"LÉGITIME (Domaine Officiel Certifié - {brand})"
        self.verdict_class = "LEGITIMATE"

        # Vérification qu'il n'y a pas d'attaque par redirection ouverte ou syntaxe d'authentification @
        if "@" in self.normalized_url:
            self.risk_score += 45
            self.findings.append({
                "category": "Obfuscation",
                "severity": "CRITICAL",
                "points": 45,
                "title": "Attaque par Syntaxe d'Authentification (@)",
                "description": "L'URL tente de masquer sa destination finale en utilisant le nom officiel avant un symbole '@'."
            })

        self.ai_summary = (
            f"Le domaine racine '{self.registered_domain}' est un domaine officiel certifié "
            f"appartenant à {brand}. Même en présence de mots-clés d'authentification (login/signin), "
            f"cette page fait partie de l'infrastructure légitime et vérifiée de l'éditeur."
        )
        self.soc_recommendations = [
            "Aucune action de blocage requise.",
            "L'infrastructure est authentique et conforme aux enregistrements officiels."
        ]

    def check_homographs(self):
        is_punycode = False
        detected_confusables = []

        try:
            encoded = self.hostname.encode("idna").decode("ascii")
            if "xn--" in encoded or "xn--" in self.hostname:
                is_punycode = True
        except Exception:
            is_punycode = True

        for char in self.hostname:
            if char in CONFUSABLE_CHARS:
                detected_confusables.append(f"'{char}' (substitut cyrillique/grec de '{CONFUSABLE_CHARS[char]}')")

        if is_punycode or detected_confusables:
            pts = 45
            self.risk_score += pts
            chars_desc = ", ".join(detected_confusables) if detected_confusables else "Préfixe xn-- détecté"
            self.findings.append({
                "category": "Homographe / Punycode",
                "severity": "CRITICAL",
                "points": pts,
                "title": "Attaque Homographe IDN Détectée",
                "description": f"Le domaine '{self.hostname}' injecte des caractères d'alphabets non-latins pour imiter visuellement une marque légitime. ({chars_desc})."
            })

    def check_brand_impersonation(self):
        """
        Détecte le typosquatting (Levenshtein), le leet-squatting (substitutions de chiffres),
        le combosquatting (marque + mot-clé) et l'usurpation via sous-domaine trompeur.
        """
        reg_main = self.registered_domain.split(".")[0]
        tokens = [t for t in re.split(r'[-_]', reg_main) if t]
        normalized_tokens = [normalize_leetspeak(t) for t in tokens]
        norm_reg_main = normalize_leetspeak(reg_main)

        for brand in OFFICIAL_BRANDS.keys():
            # 1. Vérification dans le sous-domaine (ex: paypal.com.evil-portal.xyz)
            if self.subdomains:
                sub_parts = re.split(r'[-_.]', self.subdomains.lower())
                norm_sub_parts = [normalize_leetspeak(p) for p in sub_parts]
                if brand in sub_parts or brand in norm_sub_parts or any(brand in p for p in sub_parts):
                    pts = 40
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Usurpation de Marque",
                        "severity": "CRITICAL",
                        "points": pts,
                        "title": f"Usurpation par Sous-Domaine ({brand.upper()})",
                        "description": f"Injection de la marque '{brand}' dans le sous-domaine ('{self.subdomains}') pour dissimuler le domaine réel '{self.registered_domain}'"
                    })
                    return

            # 2. Leet-Squatting direct sur token (ex: paypa1 -> paypal, micros0ft -> microsoft)
            for raw_tok, norm_tok in zip(tokens, normalized_tokens):
                if norm_tok == brand and raw_tok != brand:
                    pts = 40
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Typosquatting & Leet-Squat",
                        "severity": "CRITICAL",
                        "points": pts,
                        "title": f"Leet-Squatting sur la marque {brand.upper()}",
                        "description": f"Substitution de caractères détectée ('{raw_tok}' imite '{brand}'). Technique de tromperie visuelle pour tromper la victime."
                    })
                    return

            # 3. Typosquatting par distance de Levenshtein sur les tokens
            candidates = [reg_main] + tokens
            for cand in candidates:
                dist = levenshtein_distance(cand, brand)
                norm_dist = levenshtein_distance(normalize_leetspeak(cand), brand)
                min_dist = min(dist, norm_dist)

                if min_dist == 1 and cand != brand:
                    pts = 35
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Typosquatting",
                        "severity": "CRITICAL",
                        "points": pts,
                        "title": f"Typosquatting sur la marque {brand.upper()}",
                        "description": f"Variante trompeuse sur '{cand}' (1 caractère d'écart vs '{brand}')."
                    })
                    return
                elif min_dist == 2 and len(brand) >= 6 and cand != brand and not cand.startswith(brand):
                    pts = 30
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Typosquatting",
                        "severity": "HIGH",
                        "points": pts,
                        "title": f"Typosquatting sur la marque {brand.upper()}",
                        "description": f"Variante trompeuse sur '{cand}' (2 caractères d'écart vs '{brand}')."
                    })
                    return

            # 4. Combosquatting dans le domaine racine (ex: paypal-security.com ou paypa1-update.com)
            brand_in_domain = (brand in reg_main) or (brand in norm_reg_main)
            if brand_in_domain and reg_main != brand:
                for kw in ["secure", "security", "login", "verify", "update", "account", "support", "auth", "billing", "portal"]:
                    if kw in reg_main or kw in norm_reg_main:
                        pts = 35
                        self.risk_score += pts
                        self.findings.append({
                            "category": "Usurpation de Marque",
                            "severity": "CRITICAL",
                            "points": pts,
                            "title": f"Combosquatting Détecté ({brand.upper()})",
                            "description": f"Fusion trompeuse de la marque '{brand}' avec le terme '{kw}' dans '{self.registered_domain}'."
                        })
                        return

    def check_free_hosting_abuse(self):
        """Détecte l'utilisation de plateformes gratuites (workers.dev, vercel.app) pour héberger des faux portails."""
        for platform in FREE_HOSTING_PLATFORMS:
            if self.hostname.endswith(platform):
                # Vérifie si le sous-domaine contient une marque ou un mot de phishing
                has_brand = any(brand in self.hostname for brand in OFFICIAL_BRANDS.keys())
                has_phish_kw = any(kw in self.hostname or kw in self.path for kw in PHISHING_KEYWORDS)

                if has_brand or has_phish_kw:
                    pts = 35
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Abus d'Hébergement Cloud",
                        "severity": "HIGH",
                        "points": pts,
                        "title": f"Abus de Plateforme Cloud ({platform})",
                        "description": f"Hébergement d'une page de collecte d'identifiants sur un service éphémère gratuit ({platform}). Fréquent pour contourner les réputations de domaines."
                    })
                break

    def check_shortener(self):
        for short in SHORTENER_DOMAINS:
            if self.hostname == short or self.hostname.endswith("." + short):
                pts = 15
                self.risk_score += pts
                self.findings.append({
                    "category": "Masquage de Destination",
                    "severity": "MEDIUM",
                    "points": pts,
                    "title": f"URL Raccourcie ({short})",
                    "description": "L'URL dissimule sa destination réelle derrière un réducteur de liens."
                })
                break

    def run_network_probes(self):
        """Exécute les vérifications réseau actives (DNS, RDAP, Déroulage de redirection, TLS)."""
        # 1. Déroulage de redirection si shortener
        if any(short in self.hostname for short in SHORTENER_DOMAINS):
            redir_res = self.probe.unmask_shortener(self.normalized_url)
            if redir_res["redirect_count"] > 0 and redir_res["final_url"] != self.normalized_url:
                self.osint_data["redirect_unmasked"] = True
                self.osint_data["final_destination"] = redir_res["final_url"]
                self.findings.append({
                    "category": "Redirection Forensique",
                    "severity": "HIGH",
                    "points": 20,
                    "title": f"Redirection Démasquée ({redir_res['redirect_count']} saut(s))",
                    "description": f"L'URL courte redirige vers la cible finale : {redir_res['final_url']}"
                })
                # Analyse de la cible finale dévoilée
                try:
                    dest_analyzer = PhishAnalyzer(redir_res["final_url"], enable_network=False)
                    dest_res = dest_analyzer.analyze()
                    if dest_res["risk_score"] >= 25:
                        self.risk_score += dest_res["risk_score"]
                        for f in dest_res["findings"]:
                            self.findings.append({
                                "category": f"[Cible Finale] {f['category']}",
                                "severity": f["severity"],
                                "points": f["points"],
                                "title": f"[Cible Finale] {f['title']}",
                                "description": f["description"]
                            })
                except Exception:
                    pass

        # 2. Résolution DNS
        dns_res = self.probe.resolve_dns(self.hostname)
        if dns_res["success"]:
            self.osint_data["resolved_ip"] = dns_res["ip"]
            if dns_res["is_private"]:
                self.osint_data["ip_is_private"] = True
                pts = 35
                self.risk_score += pts
                self.findings.append({
                    "category": "Réseau Interne / SSRF",
                    "severity": "CRITICAL",
                    "points": pts,
                    "title": "Résolution vers une IP Privée / Locale",
                    "description": f"Le domaine résout vers {dns_res['ip']} (adresse réservée/locale). Indique une tentative de SSRF ou de rebond interne."
                })
        else:
            # Domaine qui ne résout pas (peut être déjà suspendu ou faux)
            self.findings.append({
                "category": "Résolution DNS",
                "severity": "LOW",
                "points": 5,
                "title": "Domaine Introuvable ou Suspendu (NXDOMAIN)",
                "description": f"Le domaine n'a pas pu être résolu en IP. L'infrastructure est peut-être déjà neutralisée ou en cours de déploiement."
            })

        # 3. Âge du domaine via RDAP
        rdap_res = self.probe.query_rdap_age(self.registered_domain)
        if rdap_res["success"]:
            self.osint_data["domain_age_days"] = rdap_res["age_days"]
            self.osint_data["domain_created"] = rdap_res["creation_date"]
            self.osint_data["registrar"] = rdap_res["registrar"]

            if rdap_res["is_brand_new"]:
                pts = 30
                self.risk_score += pts
                self.findings.append({
                    "category": "Âge du Domaine (RDAP)",
                    "severity": "CRITICAL",
                    "points": pts,
                    "title": f"Domaine Jetable Ultra-Récent ({rdap_res['age_days']} jour(s))",
                    "description": f"Le domaine a été enregistré très récemment (le {rdap_res['creation_date']} via {rdap_res['registrar']}). Indicateur majeur de campagne de phishing éphémère."
                })
            elif rdap_res["age_days"] and rdap_res["age_days"] > 730:
                # Bonus pour domaine établi depuis plus de 2 ans
                self.risk_score = max(0, self.risk_score - 10)

        # 4. Certificat TLS
        if self.normalized_url.startswith("https://") or True:
            tls_res = self.probe.inspect_tls(self.hostname)
            if tls_res["has_tls"]:
                self.osint_data["tls_issuer"] = tls_res["issuer"]
                self.osint_data["tls_is_free"] = tls_res["is_free_cert"]
                if tls_res["is_free_cert"] and any(brand in self.hostname for brand in OFFICIAL_BRANDS.keys()):
                    pts = 15
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Certificat Cryptographique",
                        "severity": "MEDIUM",
                        "points": pts,
                        "title": f"Certificat Gratuit sur Marque Bancaire/Tech ({tls_res['issuer']})",
                        "description": f"Le domaine prétend représenter une institution majeure mais utilise un certificat gratuit à courte durée ({tls_res['issuer']}) au lieu d'un certificat d'entreprise."
                    })
            else:
                if self.normalized_url.startswith("https://"):
                    pts = 20
                    self.risk_score += pts
                    self.findings.append({
                        "category": "Certificat Cryptographique",
                        "severity": "HIGH",
                        "points": pts,
                        "title": "Défaut de Certificat SSL/TLS",
                        "description": tls_res.get("error", "Aucun certificat HTTPS valide n'a pu être négocié.")
                    })

        # 5. VirusTotal
        vt_res = self.probe.query_virustotal(self.normalized_url, self.registered_domain)
        self.osint_data["vt_stats"] = vt_res
        if vt_res.get("configured") and vt_res.get("malicious_count", 0) > 0:
            pts = min(40, vt_res["malicious_count"] * 10)
            self.risk_score += pts
            self.findings.append({
                "category": "Threat Intelligence (VirusTotal)",
                "severity": "CRITICAL" if vt_res["malicious_count"] >= 3 else "HIGH",
                "points": pts,
                "title": f"Signalé par VirusTotal ({vt_res['malicious_count']} moteur(s))",
                "description": vt_res.get("message")
            })

    def check_heuristics(self):
        # Détection IP directe
        ip_pattern = r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
        if re.match(ip_pattern, self.hostname):
            pts = 30
            self.risk_score += pts
            self.findings.append({
                "category": "Structure d'Hôte",
                "severity": "HIGH",
                "points": pts,
                "title": "Adresse IP Numérique Directe",
                "description": "L'URL utilise une adresse IP brute au lieu d'un nom de domaine qualifié (FQDN). Révèle une infrastructure temporaire ou non légitime."
            })

        # TLD Suspect
        for tld, pts in SUSPICIOUS_TLDS.items():
            if self.hostname.endswith(tld):
                self.risk_score += pts
                self.findings.append({
                    "category": "Réputation TLD",
                    "severity": "MEDIUM",
                    "points": pts,
                    "title": f"TLD à Risque d'Abus ({tld})",
                    "description": f"L'extension '{tld}' est massivement surreprésentée dans les campagnes de spam et d'hameçonnage."
                })
                break

        # Sous-domaines excessifs
        dot_count = self.hostname.count(".")
        if dot_count >= 3 and not re.match(ip_pattern, self.hostname):
            pts = 15
            self.risk_score += pts
            self.findings.append({
                "category": "Structure d'Hôte",
                "severity": "MEDIUM",
                "points": pts,
                "title": f"Empilement de Sous-domaines ({dot_count} niveaux)",
                "description": "Dissimulation de l'identité du serveur par empilement de sous-domaines pour tromper l'affichage sur mobile."
            })

        # Entropie DGA
        main_part = self.registered_domain.split(".")[0]
        entropy = calculate_entropy(main_part)
        if entropy >= 3.8 and len(main_part) >= 11:
            pts = 15
            self.risk_score += pts
            self.findings.append({
                "category": "Heuristique DGA",
                "severity": "MEDIUM",
                "points": pts,
                "title": f"Entropie de Caractères Élevée ({entropy:.2f})",
                "description": "Nom de domaine aléatoire typique des générateurs DGA ou d'empreintes de serveurs éphémères."
            })

        # Séparateur d'authentification @
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
        full_str = (self.path + " " + self.query + " " + self.subdomains).lower()
        found = [kw for kw in PHISHING_KEYWORDS if kw in full_str]
        if found:
            pts = min(20, len(found) * 5)
            self.risk_score += pts
            self.findings.append({
                "category": "Ingénierie Sociale",
                "severity": "HIGH" if pts >= 15 else "MEDIUM",
                "points": pts,
                "title": "Mots-clés de Capture d'Identifiants",
                "description": f"Termes suspects identifiés : {', '.join(found[:5])}. Indique une tentative de vol d'identifiants ou de session."
            })

    def finalize_verdict(self):
        self.risk_score = min(100, self.risk_score)

        if self.osint_data["is_official_brand_domain"] and self.risk_score < 30:
            self.verdict = f"LÉGITIME (Domaine Officiel - {self.osint_data['matched_official_brand']})"
            self.verdict_class = "LEGITIMATE"
            return

        if self.risk_score >= 70:
            self.verdict = "CRITIQUE (Phishing Confirmé)"
            self.verdict_class = "CRITICAL"
        elif self.risk_score >= 40:
            self.verdict = "ÉLEVÉ (Probable Hameçonnage)"
            self.verdict_class = "HIGH"
        elif self.risk_score >= 20:
            self.verdict = "SUSPECT (Vigilance Requise)"
            self.verdict_class = "SUSPICIOUS"
        else:
            self.verdict = "FAIBLE (Domaine Légitime / Sans Anomalie)"
            self.verdict_class = "LOW"

        # Synthèse IA & Recommandations SOC
        if self.risk_score >= 40:
            critical_points = [f["title"] for f in self.findings if f["severity"] in ["CRITICAL", "HIGH"]]
            summary_reasons = " et ".join(critical_points[:2]) if critical_points else "un faisceau d'anomalies structurelles"
            self.ai_summary = (
                f"Menace qualifiée au niveau {self.verdict.split()[0]} (Score de Risque : {self.risk_score}/100). "
                f"L'analyse forensique a identifié {summary_reasons}. "
                "L'infrastructure est conçue pour détourner des accès ou voler des identifiants d'utilisateurs."
            )
            self.soc_recommendations = [
                "Bloquer immédiatement l'accès à ce domaine sur les résolveurs DNS (Sinkholing) et proxy d'entreprise.",
                "Corréler les journaux Proxy/EDR pour isoler les postes internes ayant contacté cette URL.",
                "En cas de saisie d'identifiants par un collaborateur, révoquer immédiatement ses sessions et réinitialiser son mot de passe.",
                "Ajouter l'IoC (domaine et IP résolue) aux règles de détection SIEM / Wazuh."
            ]
        else:
            self.ai_summary = (
                f"Score de risque faible ({self.risk_score}/100). "
                "Aucun indicateur d'usurpation de marque, d'attaque homographe ou de domaine jetable n'a été détecté."
            )
            self.soc_recommendations = [
                "Aucune mesure de blocage requise.",
                "Maintenir les contrôles usuels de navigation sécurisée."
            ]

    def to_dict(self):
        return {
            "target_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "domain": self.hostname,
            "registered_domain": self.registered_domain,
            "subdomains": self.subdomains,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "verdict_class": self.verdict_class,
            "osint": self.osint_data,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "ai_executive_summary": self.ai_summary,
            "soc_recommendations": self.soc_recommendations,
            "scan_timestamp": datetime.now().isoformat()
        }


# =============================================================================
# FORMATTAGE & AFFICHAGE CONSOLE
# =============================================================================
def render_ascii_gauge(score):
    """Génère une jauge graphique en blocs colorés."""
    total_blocks = 25
    filled = int((score / 100) * total_blocks)
    empty = total_blocks - filled

    if score >= 70:
        col = Colors.RED
        tag = "CRITIQUE (PHISHING CONFIRMÉ)"
    elif score >= 40:
        col = Colors.ORANGE
        tag = "ÉLEVÉ (PROBABLE HAMEÇONNAGE)"
    elif score >= 20:
        col = Colors.YELLOW
        tag = "SUSPECT (VIGILANCE REQUISE)"
    else:
        col = Colors.GREEN
        tag = "FAIBLE (LÉGITIME)"

    bar = f"{col}[{'█' * filled}{'░' * empty}] {score}/100{Colors.RESET} — {col}{Colors.BOLD}{tag}{Colors.RESET}"
    return bar


def display_cli_report(res):
    """Affiche un rapport forensique complet avec télémétrie OSINT structurée."""
    score = res["risk_score"]
    osint = res.get("osint", {})

    print("\n" + f"{Colors.CYAN}┌" + "─" * 92 + "┐" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}{Colors.WHITE}RAPPORT D'ANALYSE FORENSIQUE PHISHSCOPE-AI v3.0{Colors.RESET}{' ' * 44}{Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}├" + "─" * 92 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Cible inspectée : {Colors.BOLD}{res['normalized_url'][:70]}{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Domaine FQDN    : {Colors.CYAN}{res['domain']}{Colors.RESET} (Racine : {Colors.BOLD}{res['registered_domain']}{Colors.RESET})")
    print(f"{Colors.CYAN}│{Colors.RESET}  Horodatage      : {res['scan_timestamp'][:19]}")
    print(f"{Colors.CYAN}│{Colors.RESET}  Niveau Risque   : {render_ascii_gauge(score)}")
    print(f"{Colors.CYAN}├" + "─" * 92 + "┤" + f"{Colors.RESET}")

    # Télémétrie OSINT en direct
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}TÉLÉMÉTRIE & OSINT RÉSEAU :{Colors.RESET}")
    ip_str = osint.get('resolved_ip') or "Non résolue / Offline"
    dest_str = osint.get('final_destination') if osint.get('redirect_unmasked') else "Aucune redirection"
    age_str = f"{osint.get('domain_age_days')} jours (Enregistré le {osint.get('domain_created')})" if osint.get('domain_age_days') else "Non disponible / ccTLD"
    reg_str = osint.get('registrar') or "Inconnu"
    tls_str = osint.get('tls_issuer') or "Aucun / Inaccessible"
    if osint.get('tls_is_free'):
        tls_str += f" {Colors.YELLOW}(Certificat Gratuit / DV){Colors.RESET}"

    print(f"{Colors.CYAN}│{Colors.RESET}  • Adresse IP Résolue : {Colors.GREEN if ip_str != 'Non résolue / Offline' else Colors.GRAY}{ip_str}{Colors.RESET}")
    if osint.get('redirect_unmasked'):
        print(f"{Colors.CYAN}│{Colors.RESET}  • {Colors.YELLOW}Destination Finale (Démasquée) :{Colors.RESET} {dest_str}")
    print(f"{Colors.CYAN}│{Colors.RESET}  • Âge du Domaine (RDAP) : {Colors.RED if osint.get('domain_age_days') and osint.get('domain_age_days') <= 30 else Colors.WHITE}{age_str}{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}  • Bureau d'enregistrement : {reg_str}")
    print(f"{Colors.CYAN}│{Colors.RESET}  • Émetteur Certificat TLS : {tls_str}")

    vt = osint.get("vt_stats")
    if vt and vt.get("configured"):
        vt_col = Colors.RED if vt.get("malicious_count", 0) > 0 else Colors.GREEN
        print(f"{Colors.CYAN}│{Colors.RESET}  • Détection VirusTotal  : {vt_col}{vt.get('message')}{Colors.RESET}")

    print(f"{Colors.CYAN}├" + "─" * 92 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}SYNTHÈSE DE L'INTELLIGENCE :{Colors.RESET}")
    words = res['ai_executive_summary'].split()
    line = "  "
    for w in words:
        if len(line) + len(w) + 1 > 88:
            print(f"{Colors.CYAN}│{Colors.RESET} {line}")
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        print(f"{Colors.CYAN}│{Colors.RESET} {line}")

    print(f"{Colors.CYAN}├" + "─" * 92 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}ANOMALIES & INDICATEURS IDENTIFIÉS ({res['findings_count']}) :{Colors.RESET}")

    if not res["findings"]:
        print(f"{Colors.CYAN}│{Colors.RESET}  {Colors.GREEN}[✓] Aucun indicateur d'usurpation ou d'anomalie détecté.{Colors.RESET}")
    else:
        for f in res["findings"]:
            s_col = Colors.RED if f['severity'] == "CRITICAL" else Colors.ORANGE if f['severity'] == "HIGH" else Colors.YELLOW
            print(f"{Colors.CYAN}│{Colors.RESET}   {s_col}▶ [{f['severity']} +{f['points']}pts]{Colors.RESET} {Colors.BOLD}{f['title']}{Colors.RESET} ({f['category']})")
            print(f"{Colors.CYAN}│{Colors.RESET}     {Colors.GRAY}↳ {f['description'][:85]}{Colors.RESET}")

    print(f"{Colors.CYAN}├" + "─" * 92 + "┤" + f"{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET} {Colors.BOLD}RECOMMANDATIONS OPÉRATIONNELLES SOC :{Colors.RESET}")
    for r in res["soc_recommendations"]:
        print(f"{Colors.CYAN}│{Colors.RESET}  {Colors.YELLOW}⚡{Colors.RESET} {r}")

    print(f"{Colors.CYAN}└" + "─" * 92 + "┘" + f"{Colors.RESET}\n")


# =============================================================================
# CONSOLE INTERACTIVE (CLI SHELL)
# =============================================================================
def interactive_console():
    """Démarre une session interactive pour analyste SOC."""
    print(f"{Colors.LIGHT_GREEN}Session interactive PhishScope v3.0 démarrée.{Colors.RESET}")
    print(f"Collez une URL à auditer, ou tapez {Colors.CYAN}help{Colors.RESET} pour la liste des commandes.\n")

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
                print(f"\n{Colors.BOLD}Commandes disponibles :{Colors.RESET}")
                print(f"  {Colors.CYAN}<URL>{Colors.RESET}            : Collez directement n'importe quel lien pour analyse")
                print(f"  {Colors.CYAN}scan <URL>{Colors.RESET}       : Analyse l'URL avec les sondes OSINT actives")
                print(f"  {Colors.CYAN}fast <URL>{Colors.RESET}       : Analyse heuristique rapide (sans requêtes réseau)")
                print(f"  {Colors.CYAN}bulk <fichier>{Colors.RESET}   : Scanne une liste d'URLs depuis un fichier texte")
                print(f"  {Colors.CYAN}demo{Colors.RESET}             : Lance la suite de démonstration comparative")
                print(f"  {Colors.CYAN}history{Colors.RESET}          : Affiche les scans réalisés pendant la session")
                print(f"  {Colors.CYAN}export <fichier>{Colors.RESET} : Exporte l'historique complet en JSON")
                print(f"  {Colors.CYAN}vt-key <clé>{Colors.RESET}     : Définit la clé API VirusTotal pour la session")
                print(f"  {Colors.CYAN}clear{Colors.RESET}            : Efface l'écran")
                print(f"  {Colors.CYAN}exit{Colors.RESET}             : Quitte la console\n")

            elif cmd == "vt-key":
                if len(parts) < 2:
                    curr = os.environ.get("VT_API_KEY", "Non définie")
                    print(f"Clé VT_API_KEY actuelle : {curr[:8]}... (longueur: {len(curr)})\n")
                else:
                    os.environ["VT_API_KEY"] = parts[1]
                    print(f"{Colors.GREEN}[✓] Clé VirusTotal enregistrée pour cette session.{Colors.RESET}\n")

            elif cmd == "demo":
                run_demo()

            elif cmd == "history":
                if not history:
                    print(f"{Colors.GRAY}[i] Aucun scan dans l'historique de cette session.{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.BOLD}Historique des scans ({len(history)}) :{Colors.RESET}")
                    for idx, h in enumerate(history, 1):
                        col = Colors.RED if h['risk_score'] >= 70 else Colors.ORANGE if h['risk_score'] >= 40 else Colors.YELLOW if h['risk_score'] >= 20 else Colors.GREEN
                        print(f"  {idx}. {h['domain']:<32} -> {col}{h['risk_score']}/100 ({h['verdict_class']}){Colors.RESET}")
                    print()

            elif cmd == "export":
                out_name = parts[1] if len(parts) > 1 else "phishscope_history.json"
                with open(out_name, "w", encoding="utf-8") as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
                print(f"{Colors.GREEN}[✓] Historique exporté ({len(history)} entrées) dans :{Colors.RESET} {out_name}\n")

            elif cmd == "bulk":
                if len(parts) < 2:
                    print(f"{Colors.RED}[!] Usage : bulk <chemin_fichier.txt>{Colors.RESET}\n")
                    continue
                run_bulk_scan(parts[1])

            elif cmd == "fast":
                if len(parts) < 2:
                    print(f"{Colors.RED}[!] Usage : fast <URL>{Colors.RESET}\n")
                    continue
                analyzer = PhishAnalyzer(parts[1], enable_network=False)
                res = analyzer.analyze()
                history.append(res)
                display_cli_report(res)

            elif cmd == "scan":
                if len(parts) < 2:
                    print(f"{Colors.RED}[!] Usage : scan <URL>{Colors.RESET}\n")
                    continue
                analyzer = PhishAnalyzer(parts[1], enable_network=True)
                res = analyzer.analyze()
                history.append(res)
                display_cli_report(res)

            else:
                target = user_input
                analyzer = PhishAnalyzer(target, enable_network=True)
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
    """Analyse un fichier contenant une liste d'URLs."""
    if not os.path.exists(filepath):
        print(f"{Colors.RED}[!] Fichier introuvable :{Colors.RESET} {filepath}\n")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"\n{Colors.CYAN}[*] Début de l'audit en lot : {len(urls)} URLs dans '{filepath}'...{Colors.RESET}\n")
    print(f"{Colors.BOLD}{'#':<4} {'DOMAINE CIBLE':<32} {'SCORE':<10} {'VERDICT':<30}{Colors.RESET}")
    print("-" * 85)

    crit_count = 0
    for idx, u in enumerate(urls, 1):
        analyzer = PhishAnalyzer(u, enable_network=True)
        res = analyzer.analyze()
        score = res["risk_score"]
        col = Colors.RED if score >= 70 else Colors.ORANGE if score >= 40 else Colors.YELLOW if score >= 20 else Colors.GREEN

        if score >= 40:
            crit_count += 1

        print(f"{idx:<4} {res['domain'][:30]:<32} {col}{score}/100{Colors.RESET:<5} {col}{res['verdict']}{Colors.RESET}")

    print("-" * 85)
    print(f"Synthèse : {Colors.BOLD}{len(urls)} liens audités{Colors.RESET} | {Colors.RED}{crit_count} menace(s) qualifiée(s){Colors.RESET}\n")


# =============================================================================
# BANC D'ESSAI COMPARATIF (DEMO AVANCÉE)
# =============================================================================
def run_demo():
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}=== BANC D'ESSAI COMPARATIF PHISHSCOPE-AI v3.0 ==={Colors.RESET}\n")

    test_cases = [
        ("https://accounts.google.com/signin/v2/identifier", "1. Domaine Officiel Authentique (Google Login - Doit être certifié 0/100)"),
        ("https://paypa1-update-security.top/login.php", "2. Typosquatting PayPal + TLD Abusif (.top) + Mots-clés de Phishing"),
        ("https://paypal.com.account-verification-portal.xyz/auth", "3. Usurpation par Sous-Domaine trompeur (Subdomain Deception)"),
        ("http://аpple.com/verify-account", "4. Attaque Homographe IDN / Cyrillique ('а' cyrillique U+0430)"),
        ("https://secure-login-portal.workers.dev/auth", "5. Abus de Plateforme Cloud Gratuite (Cloudflare Workers)"),
        ("https://tinyurl.com/2p8b27s2", "6. Déroulage de Redirection Masquée (Shortener Unmasking)")
    ]

    for u, scenario in test_cases:
        print(f"{Colors.GRAY}Scénario de test : {scenario}{Colors.RESET}")
        time.sleep(0.3)
        analyzer = PhishAnalyzer(u, enable_network=True)
        res = analyzer.analyze()
        display_cli_report(res)

    print(f"{Colors.LIGHT_GREEN}[✓] Démonstration comparative achevée avec succès !{Colors.RESET}\n")


# =============================================================================
# POINT D'ENTRÉE DU SCRIPT
# =============================================================================
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="PhishScope-AI v3.0 : Console Forensique d'Analyse Anti-Phishing & OSINT",
        epilog="Exemples :\n  python phishscope.py                                 (Console interactive)\n  python phishscope.py -u https://paypa1-security.top  (Audit direct)\n  python phishscope.py -f urls.txt                     (Audit en lot)\n  python phishscope.py --demo                          (Banc d'essai comparatif)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="URL suspecte à inspecter immédiatement")
    parser.add_argument("-f", "--file", help="Fichier texte contenant une liste d'URLs à auditer en lot")
    parser.add_argument("-i", "--interactive", action="store_true", help="Ouvre la console interactive PhishScope")
    parser.add_argument("--demo", action="store_true", help="Lance le banc d'essai comparatif")
    parser.add_argument("--json", action="store_true", help="Sortie au format JSON brut pour scripts et pipelines")
    parser.add_argument("--fast", action="store_true", help="Désactive les sondes réseau actives pour un audit 100% heuristique")

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.file:
        run_bulk_scan(args.file)
        return

    if args.url:
        analyzer = PhishAnalyzer(args.url, enable_network=not args.fast)
        res = analyzer.analyze()
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            display_cli_report(res)
        return

    # Console Interactive par défaut
    interactive_console()


if __name__ == "__main__":
    main()
