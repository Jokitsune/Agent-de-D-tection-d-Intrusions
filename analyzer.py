
import json
from pathlib import Path
from datetime import datetime
from glob import glob

BASE_DIR  = Path(__file__).parent
LOGS_DIR  = BASE_DIR / "logs"
ANAL_DIR  = BASE_DIR / "analysis"

SENSITIVE_USERS = {"root", "admin", "oracle", "postgres"}

def find_log_files() -> list[Path]:

    pattern = str(LOGS_DIR / "*.log")
    return [Path(p) for p in glob(pattern)]


def parse_log(log_path: Path) -> list[dict]:
    try:
        content = log_path.read_text(encoding="utf-8")
        return json.loads(content)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[WARN] Impossible de lire {log_path.name} : {exc}")
        return []


def detect_brute_force(events: list[dict], threshold: int = 5) -> list[dict]:
    counts: dict[str, int] = {}
    for ev in events:
        if ev.get("type") == "ssh_fail":
            ip = ev.get("ip", "unknown")
            counts[ip] = counts.get(ip, 0) + 1

    alerts: list[dict] = []
    for ip, attempts in counts.items():
        if attempts >= threshold:
            alerts.append({
                "type":     "BRUTE_FORCE",
                "ip":       ip,
                "attempts": attempts,
                "severity": "HIGH"
            })
    return alerts


def detect_unusual_users(events: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    alerts: list[dict] = []

    for ev in events:
        if ev.get("type") == "ssh_fail":
            user = ev.get("user", "")
            ip   = ev.get("ip", "unknown")
            if user in SENSITIVE_USERS:
                key = (user, ip)
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        "type":     "SENSITIVE_USER",
                        "user":     user,
                        "ip":       ip,
                        "severity": "MEDIUM"
                    })
    return alerts


def save_analysis(alerts: list[dict]) -> Path:
    date_str  = datetime.now().strftime("%Y%m%d")
    out_path  = ANAL_DIR / f"analysis_{date_str}.json"
    out_path.write_text(
        json.dumps(alerts, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return out_path


# ──────────────────────────────────────────────────────────────────────────────
def run_analyze() -> None:
    log_files = find_log_files()
    fichier_logs = "fichier log" if len(log_files) == 1 else "fichiers logs"
    print(f"[ANALYZE] Analyse de {len(log_files)} {fichier_logs}...")

    if not log_files:
        print("[WARN] Aucun fichier log trouvé. Lancez d'abord --listen.")
        return


    all_events: list[dict] = []
    for lf in log_files:
        all_events.extend(parse_log(lf))

    bf_alerts   = detect_brute_force(all_events)
    user_alerts = detect_unusual_users(all_events)

    bf_alerte  = "alerte" if len(bf_alerts) == 1 else "alertes"
    bf_verbe   = "détectée" if len(bf_alerts) == 1 else "détectées"
    print(f"[INFO] {len(bf_alerts)} {bf_alerte} BRUTE_FORCE {bf_verbe}.")

    user_alerte = "alerte" if len(user_alerts) == 1 else "alertes"
    user_verbe  = "détectée" if len(user_alerts) == 1 else "détectées"
    print(f"[INFO] {len(user_alerts)} {user_alerte} SENSITIVE_USER {user_verbe}.")

    all_alerts = bf_alerts + user_alerts

    try:
        out_path = save_analysis(all_alerts)
        print(f"[INFO] Analyse sauvegardée : {out_path.relative_to(BASE_DIR)}")
    except OSError as exc:
        print(f"[ERREUR --analyze] Sauvegarde impossible : {exc}")
        raise
