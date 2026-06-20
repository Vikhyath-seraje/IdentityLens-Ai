import sqlite3

conn = sqlite3.connect('database/identitylens.db')
cursor = conn.cursor()

# 1. Create identity_groups
cursor.execute('CREATE TABLE IF NOT EXISTS identity_groups (identity_id TEXT, group_name TEXT)')

# 2. Add expires_at to ad_accounts
try:
    cursor.execute('ALTER TABLE ad_accounts ADD COLUMN expires_at TEXT')
except sqlite3.OperationalError:
    pass # Column already exists

conn.commit()
conn.close()
print("Schema updated successfully.")
