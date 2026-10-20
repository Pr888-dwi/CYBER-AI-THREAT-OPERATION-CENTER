import sqlite3
from pathlib import Path


class ThreatDatabase:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or str(Path(__file__).resolve().parent / "threats.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                explanation TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def save_alert(self, risk, attack_type, explanation):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (risk, attack_type, explanation, created_at) VALUES (?, ?, ?, datetime('now'))",
            (risk, attack_type, explanation),
        )
        conn.commit()
        conn.close()

    def list_alerts(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        rows = cursor.execute("SELECT risk, attack_type, explanation, created_at FROM alerts ORDER BY id DESC").fetchall()
        conn.close()
        return [
            {"risk": risk, "attack_type": attack_type, "explanation": explanation, "created_at": created_at}
            for risk, attack_type, explanation, created_at in rows
        ]

    def clear_alerts(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
