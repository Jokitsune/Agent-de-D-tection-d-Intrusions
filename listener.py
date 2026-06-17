"""
listener.py — Mode --listen : capture des tentatives SSH et connexions actives.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"


# ──────────────────────────────────────────────────────────────────────────────
def get_failed_logins() -> list[dict]:
    """
    Extrait les tentatives SSH échouées via journalctl ou /var/log/auth.log.
    Retourne une liste de dicts avec timestamp, ip, user, type.
    """
    events: list[dict] = []

    # ── Tentative avec journalctl ─────────────────────────────────────────
    try:
        result = subprocess.run(
            ["journalctl", "_SYSTEMD_UNIT=sshd.service", "-n", "500", "--no-pager",
             "--output=short-iso"],
            capture_output=True, text=True, timeout=10
        )
        raw_lines = result.stdout.splitlines()
        # journalctl peut répondre avec succès mais sans journal réel disponible
        # (typique en conteneur/VM de lab) : on filtre ces placeholders pour
        # déclencher correctement le fallback ci-dessous.
        lines = [
            l for l in raw_lines
            if l.strip() and not l.strip().startswith("-- No entries")
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        lines = []

    # ── Fallback : /var/log/auth.log ──────────────────────────────────────
    if not lines:
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            lines = auth_log.read_text(errors="replace").splitlines()
        else:
            # Environnement de lab sans logs réels → on génère des données simulées
            lines = _simulated_auth_lines()

    # ── Parsing ───────────────────────────────────────────────────────────
    pattern_fail = re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
        r".*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    for line in lines:
        m = pattern_fail.search(line)
        if m:
            raw_ts, user, ip = m.group(1), m.group(2), m.group(3)
            events.append({
                "timestamp": _normalize_ts(raw_ts),
                "ip":        ip,
                "user":      user,
                "type":      "ssh_fail"
            })

    return events


def get_active_connections() -> list[dict]:
    """
    Retourne les connexions TCP actives via `ss -tnp`.
    """
    events: list[dict] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        result = subprocess.run(
            ["ss", "-tnp"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Environnement sans `ss` → données simulées
        return _simulated_connections()

    # Colonnes : State Recv-Q Send-Q Local Remote
    for line in lines[1:]:  # on saute l'en-tête
        parts = line.split()
        if len(parts) < 5:
            continue
        state      = parts[0]
        local_addr = parts[3]
        remote_addr = parts[4]

        local_port  = local_addr.rsplit(":", 1)[-1]
        remote_ip   = remote_addr.rsplit(":", 1)[0].strip("[]")

        events.append({
            "timestamp":   now,
            "local_port":  local_port,
            "remote_ip":   remote_ip,
            "state":       state,
            "type":        "connection"
        })

    return events


def save_log(events: list[dict]) -> Path:
    """
    Sauvegarde les événements dans logs/capture_YYYYMMDD_HHMMSS.log.
    Retourne le Path du fichier créé.
    """
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"capture_{ts}.log"
    log_path.write_text(
        json.dumps(events, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return log_path


def purge_old_logs(retention_days: int = 7) -> None:
    """
    Supprime les fichiers de logs/ dont la date de modification dépasse retention_days.
    """
    limit = datetime.now() - timedelta(days=retention_days)
    purged = 0

    for log_file in LOGS_DIR.glob("*.log"):
        mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
        if mtime < limit:
            log_file.unlink()
            print(f"[PURGE] Fichier supprimé : {log_file.name}")
            purged += 1

    if purged == 0:
        print("[INFO] Purge : aucun fichier expiré.")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers internes
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_ts(raw: str) -> str:
    """Normalise différents formats de timestamp en 'YYYY-MM-DD HH:MM:SS'."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            # Si l'année est manquante (syslog), on injecte l'année courante
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return raw.strip()


def _simulated_auth_lines() -> list[str]:
    """Données simulées pour les environnements de lab sans journald ni auth.log."""
    return [
        "2025-06-13T14:32:11+0000 sshd[1234]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:32:15+0000 sshd[1235]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:32:20+0000 sshd[1236]: Failed password for invalid user admin from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:33:00+0000 sshd[1237]: Failed password for invalid user oracle from 10.0.0.8 port 22 ssh2",
        "2025-06-13T14:33:10+0000 sshd[1238]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:33:20+0000 sshd[1239]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:33:30+0000 sshd[1240]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:33:40+0000 sshd[1241]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:33:50+0000 sshd[1242]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:34:00+0000 sshd[1243]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:34:10+0000 sshd[1244]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:34:20+0000 sshd[1245]: Failed password for root from 192.168.1.42 port 22 ssh2",
        "2025-06-13T14:35:00+0000 sshd[1246]: Failed password for postgres from 10.0.0.9 port 22 ssh2",
    ]


def _simulated_connections() -> list[dict]:
    """Connexions simulées pour les environnements sans `ss`."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        {"timestamp": now, "local_port": "22",  "remote_ip": "10.0.0.5",  "state": "ESTABLISHED", "type": "connection"},
        {"timestamp": now, "local_port": "443", "remote_ip": "172.16.0.3", "state": "ESTABLISHED", "type": "connection"},
    ]


# ──────────────────────────────────────────────────────────────────────────────
def run_listen() -> None:
    """Point d'entrée du mode --listen."""
    print("[LISTEN] Démarrage de la capture...")

    try:
        failed = get_failed_logins()
        print(f"[INFO] {len(failed)} tentatives SSH échouées détectées.")

        connections = get_active_connections()
        print(f"[INFO] {len(connections)} connexions actives détectées.")

        all_events = failed + connections
        log_path   = save_log(all_events)
        print(f"[INFO] Log sauvegardé : {log_path.relative_to(BASE_DIR)}")

        purge_old_logs()

    except Exception as exc:
        print(f"[ERREUR --listen] {exc}")
        raise
