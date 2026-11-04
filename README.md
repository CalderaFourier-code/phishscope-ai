# 🛡️ PhishScope-AI — Console CLI d'Analyse Anti-Phishing & OSINT

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Interface](https://img.shields.io/badge/Interface-100%25%20CLI%20Console-green?logo=gnometerminal)](https://github.com/CalderaFourier-code)
[![Security](https://img.shields.io/badge/Threat%20Intel-Anti--Phishing-red?logo=kalilinux)](https://github.com/CalderaFourier-code)
[![OSINT](https://img.shields.io/badge/OSINT-Homographes%20%26%20Typosquatting-orange)](https://github.com/CalderaFourier-code)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Auteur-Tohon%20Fourier-brightgreen)](https://github.com/CalderaFourier-code)

**PhishScope-AI** est une console CLI interactive d'investigation forensique et de Threat Intelligence conçue pour disséquer les URLs suspectes directement dans le terminal. L'outil identifie les attaques par homographes (Punycode / Cyrillique), le typosquatting par distance de Levenshtein, les raccourcisseurs d'URL, les anomalies d'entropie et génère un rapport enrichi avec **jauge ASCII de score de risque (0-100)** et recommandations SOC.

Conçu sous forme d'**application autonome ultra-portable sans aucune dépendance externe obligatoire** (utilise la bibliothèque standard Python), il s'exécute immédiatement sur n'importe quel système (Linux, Windows, macOS, Kali).

---

## 🌟 Moteurs de Détection Intégrés

1. 🔤 **Moteur Anti-Homographes (IDN Spoofing & Confusables) :**
   - Détection des caractères Cyrilliques ou Grecs visuellement identiques aux lettres latines (ex: `аpple.com` avec un `а` cyrillique U+0430 au lieu de `a` latin).
   - Analyse et décodage automatique du préfixe Punycode (`xn--...`).
2. 🎯 **Moteur de Typosquatting & Combosquatting :**
   - Calcul de la **distance de Levenshtein** contre les marques à haute valeur cible (Google, Microsoft, Apple, PayPal, Netflix, Amazon, Binance, WhatsApp, MTN, Moov, Orange, Ecobank, etc.).
   - Détection des variantes trompeuses (`paypa1-update-security.top`, `login-apple-support`).
3. 🔗 **Détecteur de Masquage d'URL :**
   - Repérage des réducteurs d'URL (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.) utilisés pour dissimuler la destination finale.
4. 🧬 **Heuristiques & Entropie de Shannon :**
   - Détection des domaines générés aléatoirement (DGA).
   - Détection des adresses IP numériques directes (`http://192.168.1.1/login`).
   - Surveillance des TLDs à forte teneur d'abus (`.top`, `.xyz`, `.click`, `.buzz`, `.tk`, etc.).
   - Alerte sur les sous-domaines excessifs pour tromper l'affichage sur mobile.
   - Détection de l'obfuscation par syntaxe d'authentification (`http://legit.com@phishingsite.com`).
5. 🤖 **Calculateur de Risque & Recommandations SOC :**
   - Jauge graphique en caractères ASCII colorés : **LÉGITIME** (0-24), **SUSPECT** (25-49), **ÉLEVÉ** (50-79), **CRITIQUE** (80-100).
   - Recommandations tactiques pour les analystes SOC (blocage DNS, corrélation proxy, révocation de sessions).

---

## 🚀 Utilisation en Ligne de Commande

### 1. Démarrer la Console Interactive (Mode Shell Dédié)
Lancez simplement le script sans argument ou double-cliquez sur `lancer_phishscope.bat` :
```bash
python phishscope.py
```
Vous entrez dans la console interactive :
```text
phishscope@fourier> https://paypa1-update-security.top/login
phishscope@fourier> scan http://аpple.com/verify
phishscope@fourier> bulk urls_sample.txt
phishscope@fourier> history
phishscope@fourier> export session_audit.json
phishscope@fourier> exit
```

### 2. Scanner une URL en commande directe (One-Shot)
```bash
python phishscope.py -u "https://paypa1-update-security.top/login"
```

### 3. Scanner une liste d'URLs en lot (Bulk Triage)
Idéal pour analyser un dump d'alertes ou d'emails suspects :
```bash
python phishscope.py -f urls_sample.txt
```

### 4. Sortie JSON brute (pour pipelines & intégration SIEM)
```bash
python phishscope.py -u "http://аpple.com" --json
```

### 5. Lancer le banc d'essai automatisé (Demo)
```bash
python phishscope.py --demo
```

---

## 📸 Aperçu de la Console Terminal

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ RAPPORT D'ANALYSE FORENSIQUE PHISHSCOPE-AI                                             │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Cible inspectée : https://paypa1-update-security.top/login
│  Domaine extrait : paypa1-update-security.top
│  Horodatage      : 2026-11-01T03:51:04
│  Niveau Risque   : [██████████████████░░░░░░░] 75/100 — ÉLEVÉ (PROBABLE HAMEÇONNAGE)
├────────────────────────────────────────────────────────────────────────────────────────┤
│ SYNTHÈSE DE L'INTELLIGENCE :
│   Menace qualifiée au niveau ÉLEVÉ (Score de Risque : 75/100). L'analyse a 
│   identifié Usurpation de la marque 'PAYPAL' et Mots-clés de Capture 
│   d'Identifiants. L'infrastructure est conçue pour détourner des accès ou voler des 
│   identifiants d'utilisateurs. 
├────────────────────────────────────────────────────────────────────────────────────────┤
│ INDICATEURS OSINT & ANOMALIES IDENTIFIÉES (3) :
│   ▶ [CRITICAL +35pts] Usurpation de la marque 'PAYPAL' (Typosquatting & Usurpation)
│     ↳ Le domaine tente d'imiter la marque paypal. Technique : Typosquatting sur 'paypa
│   ▶ [MEDIUM +25pts] TLD à Risque d'Abus (.top) (Réputation TLD)
│     ↳ L'extension '.top' est massivement surreprésentée dans les campagnes de spam.
│   ▶ [HIGH +15pts] Mots-clés de Capture d'Identifiants (Ingénierie Sociale)
│     ↳ Mots suspects identifiés : login, security, update.
├────────────────────────────────────────────────────────────────────────────────────────┤
│ RECOMMANDATIONS OPÉRATIONNELLES SOC :
│  ⚡ Bloquer l'accès à ce domaine sur les résolveurs DNS (Sinkholing) et proxy.
│  ⚡ Rechercher dans les journaux réseau les postes internes ayant contacté cette URL.
│  ⚡ En cas de saisie d'identifiants par un agent, réinitialiser immédiatement son mot de passe.
│  ⚡ Ajouter l'indicateur (IoC) à la liste de surveillance du SIEM.
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Architecture du Projet

```text
phishscope-ai/
├── phishscope.py           # Console CLI interactive & Moteur d'analyse
├── lancer_phishscope.bat   # Lanceur rapide console pour Windows
├── urls_sample.txt         # Échantillons de test pour scan en lot
└── README.md               # Documentation technique
```

---

## 👤 Auteur

**Tohon Fourier**
- Spécialiste Cybersécurité Offensive & Défensive · DevSecOps
- GitHub : [@CalderaFourier-code](https://github.com/CalderaFourier-code)
- Email : [fouriertohon@gmail.com](mailto:fouriertohon@gmail.com)
