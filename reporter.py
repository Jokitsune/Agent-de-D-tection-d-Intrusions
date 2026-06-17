"""
reporter.py — Mode --report : génération du rapport d'incident et archivage.
"""

import sys
import platform
import shutil
import tarfile
import json
from pathlib import Path
from datetime import datetime
from glob import glob

BASE_DIR    = Path(__file__).parent
ANAL_DIR    = BASE_DIR / "analysis"
REPORTS_DIR = BASE_DIR / "reports"


# ──────────────────────────────────────────────────────────────────────────────
def collect_system_info() -> dict:
    """
    Collecte les informations système via platform et sys.
    """
    return {
        "date":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "machine":      platform.node(),
        "os":           f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "python":       sys.version.split()[0],
    }


def check_disk_space() -> dict:
    """
    Retourne l'espace disque (total, used, free en Go) via shutil.disk_usage.
    Ajoute un warning si l'espace libre < 10 %.
    """
    usage = shutil.disk_usage("/")
    total_go = usage.total / (1024 ** 3)
    used_go  = usage.used  / (1024 ** 3)
    free_go  = usage.free  / (1024 ** 3)
    pct_free = (usage.free / usage.total) * 100

    result = {
        "total_go": round(total_go, 1),
        "used_go":  round(used_go,  1),
        "free_go":  round(free_go,  1),
        "pct_free": round(pct_free, 1),
        "warning":  pct_free < 10,
    }
    return result


def _load_correlation() -> dict:
    """Charge le dernier fichier de corrélation disponible."""
    files = sorted(glob(str(ANAL_DIR / "correlation_*.json")), reverse=True)
    if not files:
        return {}
    try:
        return json.loads(Path(files[0]).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _load_analysis_alerts() -> list[dict]:
    """Charge toutes les alertes d'analyse pour le détail par IP."""
    files = glob(str(ANAL_DIR / "analysis_*.json"))
    alerts: list[dict] = []
    for f in files:
        try:
            data = json.loads(Path(f).read_text(encoding="utf-8"))
            if isinstance(data, list):
                alerts.extend(data)
        except (json.JSONDecodeError, OSError):
            pass
    return alerts


def generate_report(system_info: dict, correlation: dict, disk: dict) -> Path:
    """
    Génère le rapport texte dans reports/report_YYYYMMDD_HHMMSS.txt.
    """
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = REPORTS_DIR / f"report_{ts}.txt"

    # Comptage des niveaux de risque
    high = sum(1 for d in correlation.values() if d.get("risk_level") == "HIGH")
    med  = sum(1 for d in correlation.values() if d.get("risk_level") == "MEDIUM")
    low  = sum(1 for d in correlation.values() if d.get("risk_level") == "LOW")
    nb_ips = len(correlation)

    # Détail des alertes brutes pour enrichir le rapport
    raw_alerts = _load_analysis_alerts()

    lines: list[str] = [
        "========================================",
        "     RAPPORT D'INCIDENT SECURITE",
        "========================================",
        f"Date         : {system_info['date']}",
        f"Machine      : {system_info['machine']}",
        f"OS           : {system_info['os']}",
        f"Architecture : {system_info['architecture']}",
        f"Python       : {system_info['python']}",
        "----------------------------------------",
        "ESPACE DISQUE",
        f"  Total : {disk['total_go']} Go | Libre : {disk['free_go']} Go ({disk['pct_free']}%)",
    ]
    if disk["warning"]:
        lines.append("  [WARNING] Espace disque faible (< 10%) !")

    lines += [
        "----------------------------------------",
        "SYNTHESE DES RISQUES",
        f"  IPs analysees : {nb_ips} | HIGH: {high}  MEDIUM: {med}  LOW: {low}",
        "----------------------------------------",
        "DETAIL PAR IP",
    ]

    for ip, data in correlation.items():
        level = data.get("risk_level", "LOW")
        score = data.get("total_score", 0)
        lines.append(f"  {ip} → {level} (score: {score})")

        # Chercher les alertes brutes correspondant à cette IP
        ip_alerts = [a for a in raw_alerts if a.get("ip") == ip]
        for a in ip_alerts:
            atype = a.get("type", "?")
            if atype == "BRUTE_FORCE":
                lines.append(f"    - BRUTE_FORCE ({a.get('attempts', '?')} tentatives)")
            elif atype == "SENSITIVE_USER":
                lines.append(f"    - SENSITIVE_USER ({a.get('user', '?')})")
            elif atype == "PORT_SCAN":
                lines.append(f"    - PORT_SCAN")

    lines.append("========================================")

    report_text = "\n".join(lines) + "\n"
    out_path.write_text(report_text, encoding="utf-8")
    return out_path


def archive_report(report_path: Path) -> Path:
    """
    Compresse le rapport en .tar.gz dans reports/.
    Utilise arcname pour ne stocker que le nom du fichier.
    """
    date_str   = datetime.now().strftime("%Y%m%d")
    archive_path = REPORTS_DIR / f"report_{date_str}.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(report_path, arcname=report_path.name)

    return archive_path


# ──────────────────────────────────────────────────────────────────────────────
def run_report() -> None:
    """Point d'entrée du mode --report."""
    print("[REPORT] Collecte des informations système...")

    try:
        system_info  = collect_system_info()
        disk         = check_disk_space()
        correlation  = _load_correlation()

        if not correlation:
            print("[WARN] Aucune donnée de corrélation. Lancez d'abord --correlate.")

        print("[REPORT] Génération du rapport...")
        report_path  = generate_report(system_info, correlation, disk)
        print(f"[INFO] Rapport écrit : {report_path.relative_to(BASE_DIR)}")

        archive_path = archive_report(report_path)
        print(f"[INFO] Archive créée : {archive_path.relative_to(BASE_DIR)}")

        print("[SUCCES] Pipeline terminé.")

    except OSError as exc:
        print(f"[ERREUR --report] {exc}")
        raise
