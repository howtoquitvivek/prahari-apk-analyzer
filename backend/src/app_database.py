import sqlite3
import os

class db :
    def init_database():
        """Initialize SQLite database"""
        db_path = '../../database/app.db'
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_info TEXT NOT NULL,              -- JSON string
                apk_metadata TEXT NOT NULL,           -- JSON string
                certificate_info TEXT NOT NULL,       -- JSON string
                permissions TEXT NOT NULL,             -- JSON string
                flags TEXT NOT NULL,                  -- JSON string
                ml_prediction_result TEXT NOT NULL,   -- JSON string
                analysis_timestamp TEXT NOT NULL      -- duplicate for fast filtering
            )
        ''')

        
        conn.commit()
        conn.close()
        print("Database initialized successfully!")
