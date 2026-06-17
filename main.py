"""
main.py — Point d'entrée unique de l'agent de détection d'intrusions.
"""

import sys
import os
import argparse
from pathlib import Path

# ── 1. Vérification Python ≥ 3.10 ──────────────────────────────────────────
if sys.version_info < (3, 10):
    print("[ERREUR] Python 3.10 ou supérieur est requis.", file=sys.stderr)
    sys.exit(1)

# ── 2. Création de l'arborescence ──────────────────────────────────────────
BASE_DIR = Path(__file__).parent
for folder in ("logs", "analysis", "reports"):
    (BASE_DIR / folder).mkdir(parents=True, exist_ok=True)

# ── 3. Variable d'environnement AGENT_DEBUG ────────────────────────────────
if os.environ.get("AGENT_DEBUG") == "1":
    print(f"[DEBUG] Exécutable Python : {sys.executable}")

# ── 4. Argparse ────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent de Détection d'Intrusions — Pipeline 4 modes"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--listen",    action="store_true", help="Capture les tentatives SSH")
    group.add_argument("--analyze",   action="store_true", help="Analyse les logs et détecte les patterns")
    group.add_argument("--correlate", action="store_true", help="Corrèle les événements et calcule le score de risque")
    group.add_argument("--report",    action="store_true", help="Génère le rapport d'incident consolidé")
    group.add_argument("--all",       action="store_true", help="Enchaîne les 4 modes dans l'ordre")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── 5. Aucun mode fourni ───────────────────────────────────────────────
    if not any([args.listen, args.analyze, args.correlate, args.report, args.all]):
        parser.print_help()
        print("\n[ERREUR] Aucun mode fourni. Utilisez --listen, --analyze, --correlate, --report ou --all.",
              file=sys.stderr)
        sys.exit(1)

    # Import tardif pour éviter les erreurs si les modules sont absents
    from listener   import run_listen
    from analyzer   import run_analyze
    from correlator import run_correlate
    from reporter   import run_report

    try:
        if args.listen or args.all:
            run_listen()
        if args.analyze or args.all:
            run_analyze()
        if args.correlate or args.all:
            run_correlate()
        if args.report or args.all:
            run_report()
    except KeyboardInterrupt:
        print("\n[INFO] Interruption utilisateur.")
        sys.exit(0)
    except Exception as exc:
        print(f"[ERREUR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
