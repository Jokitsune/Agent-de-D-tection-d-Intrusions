"""
correlator.py — Mode --correlate : corrélation des alertes et calcul du score de risque.
"""

import json
from pathlib import Path
from datetime import datetime
from glob import glob

BASE_DIR = Path(__file__).parent
ANAL_DIR = BASE_DIR / "analysis"

# ── Tableau des scores ────────────────────────────────────────────────────────
SCORE_TABLE: dict[str, int] = {
    "BRUTE_FORCE":    30,
    "SENSITIVE_USER": 20,
    "PORT_SCAN":      25,
}


def _risk_level(score: int) -> str:
    if score > 40:
        return "HIGH"
    if score > 20:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────────────────
def load_analyses() -> list[dict]:
    """
    Utilise glob pour trouver tous les fichiers analysis/*.json (hors corrélation).
    Charge et fusionne les alertes.
    """
    pattern = str(ANAL_DIR / "analysis_*.json")
    files   = [Path(p) for p in glob(pattern)]
    alerts: list[dict] = []

    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, list):
                alerts.extend(data)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[WARN] Impossible de lire {f.name} : {exc}")

    return alerts


def correlate_by_ip(alerts: list[dict]) -> dict:
    """
    Regroupe les alertes par IP, calcule le score cumulé et le niveau de risque.
    Retourne un dictionnaire indexé par IP.
    """
    result: dict[str, dict] = {}

    for alert in alerts:
        # Les alertes BRUTE_FORCE et PORT_SCAN ont un champ 'ip'
        # Les alertes SENSITIVE_USER ont aussi un champ 'ip'
        ip    = alert.get("ip", "unknown")
        atype = alert.get("type", "UNKNOWN")
        score = SCORE_TABLE.get(atype, 0)

        if ip not in result:
            result[ip] = {"total_score": 0, "alerts": [], "risk_level": "LOW"}

        result[ip]["total_score"] += score
        if atype not in result[ip]["alerts"]:
            result[ip]["alerts"].append(atype)

    # Calcul des niveaux de risque
    for ip_data in result.values():
        ip_data["risk_level"] = _risk_level(ip_data["total_score"])

    return result


def save_correlation(result: dict) -> Path:
    """
    Sauvegarde dans analysis/correlation_YYYYMMDD.json avec pathlib.
    """
    date_str = datetime.now().strftime("%Y%m%d")
    out_path = ANAL_DIR / f"correlation_{date_str}.json"
    out_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return out_path


# ──────────────────────────────────────────────────────────────────────────────
def run_correlate() -> None:
    """Point d'entrée du mode --correlate."""
    alerts = load_analyses()

    # Compter le nombre de fichiers source (on recharge la liste pour l'affichage)
    nb_files = len([Path(p) for p in glob(str(ANAL_DIR / "analysis_*.json"))])
    print(f"[CORRELATE] Chargement de {nb_files} fichier(s) d'analyse...")

    if not alerts:
        print("[WARN] Aucune alerte à corréler. Lancez d'abord --analyze.")
        return

    corr = correlate_by_ip(alerts)
    print(f"[INFO] {len(corr)} IP(s) corrélée(s).")

    for ip, data in corr.items():
        level = data["risk_level"]
        score = data["total_score"]
        if level == "HIGH":
            print(f"[ALERTE] {ip} → score {score} → risque {level}")
        else:
            print(f"[INFO]   {ip} → score {score} → risque {level}")

    try:
        out_path = save_correlation(corr)
        print(f"[INFO] Corrélation sauvegardée : {out_path.relative_to(BASE_DIR)}")
    except OSError as exc:
        print(f"[ERREUR --correlate] Sauvegarde impossible : {exc}")
        raise
