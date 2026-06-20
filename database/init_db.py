import sqlite3
import pandas as pd
import os
import glob

DB_PATH = 'database/identitylens.db'
DATA_DIR = 'data'

# Account/source tables that get reloaded when resetting the demo back to a clean state.
ACCOUNT_TABLES = [
    'ad_accounts', 'aws_accounts', 'okta_accounts', 'api_tokens',
    'audit_logs', 'hr_records', 'identities', 'offboarding_records',
    'risk_labels', 'group_memberships', 'identity_groups'
]

# Columns added to quarantine_records to support the post-quarantine demo flow
# (before/after risk + remediation counts). All nullable so old rows stay valid.
_QUARANTINE_RECORD_EXTENSIONS = [
    ('pre_risk_score', 'INTEGER'),
    ('pre_risk_level', 'TEXT'),
    ('post_risk_score', 'INTEGER'),
    ('post_risk_level', 'TEXT'),
    ('tokens_revoked', 'INTEGER'),
    ('privileges_removed', 'INTEGER'),
]


def _existing_columns(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def ensure_quarantine_schema(conn):
    """Create the quarantine tables if missing and migrate quarantine_records in place."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS quarantine_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            pre_quarantine_state TEXT,
            status TEXT CHECK(status IN ("quarantined","released")) NOT NULL DEFAULT "quarantined",
            pre_risk_score INTEGER,
            pre_risk_level TEXT,
            post_risk_score INTEGER,
            post_risk_level TEXT,
            tokens_revoked INTEGER,
            privileges_removed INTEGER
        )
    ''')

    # In-place migration for DBs where quarantine_records was created before these
    # columns existed (ALTER TABLE ADD COLUMN is idempotent via the existence check).
    existing = _existing_columns(conn, 'quarantine_records')
    for col, col_type in _QUARANTINE_RECORD_EXTENSIONS:
        if col not in existing:
            conn.execute(f"ALTER TABLE quarantine_records ADD COLUMN {col} {col_type}")

    conn.execute('''
        CREATE TABLE IF NOT EXISTS quarantine_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            identity_id TEXT NOT NULL,
            action TEXT NOT NULL,
            platform TEXT,
            detail TEXT,
            run_id TEXT
        )
    ''')
    conn.commit()


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

    ensure_quarantine_schema(conn)
    print("Quarantine tables ensured.")

    print("Database initialization complete.")
    conn.close()


def reload_account_data(conn):
    """Restore the source account tables to their original CSV contents (demo reset)."""
    for table_name in ACCOUNT_TABLES:
        csv_path = os.path.join(DATA_DIR, f'{table_name}.csv')
        if not os.path.exists(csv_path):
            continue
        df = pd.read_csv(csv_path)
        df.to_sql(table_name, conn, if_exists='replace', index=False)


def truncate_quarantine_tables(conn):
    """Wipe all quarantine state so the demo can be re-run from a clean slate."""
    conn.execute("DELETE FROM quarantine_records")
    conn.execute("DELETE FROM quarantine_audit_events")
    conn.commit()


def reset_demo_state():
    """Reset the platform to its initial state: original accounts + empty quarantine."""
    conn = sqlite3.connect(DB_PATH)
    try:
        ensure_quarantine_schema(conn)
        reload_account_data(conn)
        truncate_quarantine_tables(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
