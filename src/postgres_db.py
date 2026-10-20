import os
import psycopg2
from psycopg2.extras import RealDictCursor


class PostgresStore:
    def __init__(self, connection_string=None):
        self.connection_string = connection_string or os.getenv("DATABASE_URL")
        self._init_db()

    def _init_db(self):
        if not self.connection_string:
            return
        conn = psycopg2.connect(self.connection_string)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                risk TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                explanation TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.close()

    def save_alert(self, risk, attack_type, explanation):
        if not self.connection_string:
            return None
        conn = psycopg2.connect(self.connection_string)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (risk, attack_type, explanation) VALUES (%s, %s, %s)",
            (risk, attack_type, explanation),
        )
        conn.commit()
        conn.close()
        return True
