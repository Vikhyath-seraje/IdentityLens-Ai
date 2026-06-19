import sqlite3
import pandas as pd
import os
import glob

DB_PATH = 'database/identitylens.db'
DATA_DIR = 'data'

def init_db():
    print(f"Initializing SQLite database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    
    csv_files = glob.glob(os.path.join(DATA_DIR, '*.csv'))
    
    for file_path in csv_files:
        table_name = os.path.basename(file_path).replace('.csv', '')
        print(f"Loading {file_path} into table '{table_name}'...")
        try:
            df = pd.read_csv(file_path)
            df.to_sql(table_name, conn, if_exists='replace', index=False)
            print(f"Successfully loaded {len(df)} records into '{table_name}'.")
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            
    # Ensure quarantine_records table exists
    conn.execute('''
        CREATE TABLE IF NOT EXISTS quarantine_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            pre_quarantine_state TEXT,
            status TEXT CHECK(status IN ("quarantined","released")) NOT NULL DEFAULT "quarantined"
        )
    ''')
    print("Quarantine table ensured.")
    
    print("Database initialization complete.")

if __name__ == "__main__":
    init_db()
