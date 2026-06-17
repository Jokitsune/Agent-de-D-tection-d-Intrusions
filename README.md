# Agent de Détection d'Intrusions — Sécurité Informatique L3

1. Description du projet et objectif

Ce projet implémente un **pipeline de détection d'intrusions en 4 modes** pour surveiller un serveur Linux exposé.  
Il capture les tentatives de connexion SSH suspectes, analyse les patterns d'attaque, corrèle les événements par adresse IP avec un score de risque, puis génère un rapport d'incident complet archivé en `.tar.gz`.

---

2. Prérequis et installation

- **Python 3.10 ou supérieur**
- **Aucune dépendance externe** — uniquement la bibliothèque standard Python
- Systèmes supportés : Linux, Windows 

Vérification de la version Python :

python3 --version


Cloner / copier le projet puis se placer dans le répertoire :
```
cd security_agent/
```

3. Utilisation

Modes séparés
```
# Capture des tentatives SSH
python main.py --listen

# Analyse des logs et détection de patterns
python main.py --analyze

# Corrélation des événements et calcul du score de risque
python main.py --correlate

# Génération du rapport d'incident
python main.py --report
```

### Mode tout-en-un (enchaîne les 4 modes dans l'ordre)
``
python main.py --all
``

### Mode debug (affiche le chemin de l'exécutable Python)
```
export AGENT_DEBUG=1
python main.py --all
```

### Aide
```
python main.py --help
```

## 4. Description de chaque module

### `main.py` — Point d'entrée unique
- Vérifie que Python ≥ 3.10 (`sys.version_info`), sinon `sys.exit(1)`
- Crée l'arborescence `logs/`, `analysis/`, `reports/` avec `pathlib`
- Lit la variable `AGENT_DEBUG` via `os.environ.get()`
- Parse les arguments `--listen`, `--analyze`, `--correlate`, `--report`, `--all` avec `argparse`

### `listener.py` — Mode `--listen`
| Fonction | Rôle |
|---|---|
| `get_failed_logins()` | Extrait les tentatives SSH échouées via `journalctl` ou `/var/log/auth.log` (fallback simulé en lab) |
| `get_active_connections()` | Retourne les connexions TCP actives via `ss -tnp` |
| `save_log(events)` | Sauvegarde les événements dans `logs/capture_YYYYMMDD_HHMMSS.log` |
| `purge_old_logs(retention_days)` | Supprime les logs expirés via `os.path.getmtime()` et `datetime` |

**Modules utilisés :** `subprocess`, `pathlib`, `os`, `datetime`, `json`

### `analyzer.py` — Mode `--analyze`
| Fonction | Rôle |
|---|---|
| `find_log_files()` | Trouve tous les fichiers `logs/*.log` via `glob` |
| `parse_log(log_path)` | Lit et parse un fichier log avec `pathlib` |
| `detect_brute_force(events, threshold)` | Détecte les IPs avec ≥ 5 tentatives SSH → alerte `BRUTE_FORCE` |
| `detect_unusual_users(events)` | Détecte les tentatives sur `root`, `admin`, `oracle`, `postgres` |
| `save_analysis(alerts)` | Sauvegarde les alertes en JSON dans `analysis/` |

**Modules utilisés :** `glob`, `pathlib`, `json`, `datetime`

### `correlator.py` — Mode `--correlate`
| Fonction | Rôle |
|---|---|
| `load_analyses()` | Charge et fusionne tous les fichiers `analysis_*.json` via `glob` |
| `correlate_by_ip(alerts)` | Regroupe par IP, calcule le score cumulé et le niveau de risque |
| `save_correlation(result)` | Sauvegarde dans `analysis/correlation_YYYYMMDD.json` |

**Tableau des scores :** `BRUTE_FORCE` +30 · `SENSITIVE_USER` +20 · `PORT_SCAN` +25  
**Niveaux :** score > 40 → HIGH · score > 20 → MEDIUM · sinon → LOW

**Modules utilisés :** `glob`, `pathlib`, `json`, `datetime`

### `reporter.py` — Mode `--report`
| Fonction | Rôle |
|---|---|
| `collect_system_info()` | Collecte OS, architecture, machine, Python via `platform` et `sys` |
| `check_disk_space()` | Retourne l'espace disque via `shutil.disk_usage()`, warning si < 10 % libre |
| `generate_report(...)` | Génère le rapport texte complet dans `reports/report_YYYYMMDD_HHMMSS.txt` |
| `archive_report(report_path)` | Compresse en `.tar.gz` via `tarfile` mode `"w:gz"` |

**Modules utilisés :** `platform`, `sys`, `shutil`, `tarfile`, `pathlib`, `datetime`, `json`, `glob`


## 5. Répartition des tâches au sein du groupe

| Membre | Module(s) pris en charge |
|---|---|
| Membre 1 | `main.py` (argparse, arborescence, vérifications sys) |
| Membre 2 | `listener.py` (capture SSH, connexions actives, purge) |
| Membre 3 | `analyzer.py` (glob, détection brute force et utilisateurs sensibles) |
| Membre 4 | `correlator.py` (scoring, niveaux de risque, corrélation par IP) |
| Membre 1 | `reporter.py` (rapport, informations système, archivage tar.gz) + `README.md` |

> Adapter selon la composition réelle du groupe (4 à 5 membres).

---

## Structure du projet

```
security_agent/
├── main.py        ← point d'entrée unique (argparse)
├── listener.py    ← mode --listen
├── analyzer.py    ← mode --analyze
├── correlator.py  ← mode --correlate
├── reporter.py    ← mode --report
├── README.md      ← documentation technique
├── logs/          ← logs bruts capturés
├── analysis/      ← données analysées (JSON)
└── reports/       ← rapports finaux + archives
```
