import sqlite3
import os
from datetime import datetime


class DatabaseHandler:
    def __init__(self, db_dir, db_name=None):
        self.db_dir = db_dir
        if db_name is None:  # make new db
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            db_name = f'interactions_{timestamp}.db'
        
        db_path = os.path.join(self.db_dir, db_name)
        
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS interactions (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                payload TEXT,
                url TEXT,
                method TEXT,
                request_headers TEXT,
                request_body TEXT,
                status_code INTEGER,
                response_headers TEXT,
                response_body TEXT
            )
        ''')
        self.conn.commit()

    def save_interaction(self, payload_index, request, response, payload):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO interactions (id, timestamp, payload, url, method, request_headers, request_body, status_code, response_headers, response_body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payload_index,
            datetime.now().isoformat(),
            payload,
            request.url,
            request.method,
            str(dict(request.headers)),
            request.body.decode('utf-8') if request.body else '',
            response.status_code,
            str(dict(response.headers)),
            response.text
        ))
        self.conn.commit()

    def load_interactions(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM interactions')
        return cursor.fetchall()

    def close(self):
        self.conn.close()

    @staticmethod
    def get_latest_db(db_dir):
        db_files = [f for f in os.listdir(db_dir) if f.endswith('.db')]
        if not db_files:
            raise FileNotFoundError("No database files found in the interactions directory.")
        latest_db = max(db_files, key=lambda x: os.path.getctime(os.path.join(db_dir, x)))
        print(f"No db was specified, using the latest db: {latest_db}\n")

        return latest_db
