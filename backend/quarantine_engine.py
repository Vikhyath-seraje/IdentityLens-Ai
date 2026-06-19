import sqlite3
import json
import datetime
from backend.risk_engine import RiskEngine

DB_PATH = 'database/identitylens.db'


def _get_timestamp():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def _snapshot_state(identity_id, conn):
    """Capture current AD, AWS, Okta, and token rows for the identity as JSON."""
    snapshot = {}
    ad = conn.execute("SELECT * FROM ad_accounts WHERE identity_id = ?", (identity_id,)).fetchone()
    snapshot['ad'] = dict(ad) if ad else None
    aws = conn.execute("SELECT * FROM aws_accounts WHERE identity_id = ?", (identity_id,)).fetchone()
    snapshot['aws'] = dict(aws) if aws else None
    okta = conn.execute("SELECT * FROM okta_accounts WHERE identity_id = ?", (identity_id,)).fetchone()
    snapshot['okta'] = dict(okta) if okta else None
    tokens = conn.execute("SELECT * FROM api_tokens WHERE identity_id = ?", (identity_id,)).fetchall()
    snapshot['tokens'] = [dict(t) for t in tokens]
    return json.dumps(snapshot)


def quarantine_identity(identity_id: str) -> str:
    """Quarantine an identity across all platforms."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        engine = RiskEngine()
        df = engine.calculate_risk_scores()
        row = df[df['identity_id'] == identity_id]
        if row.empty:
            return f"Identity {identity_id} not found."
        risk_score = int(row['risk_score'].iloc[0])
        risk_level = row['risk_level'].iloc[0]
        if not (risk_score > 75 or risk_level == 'Critical'):
            return f"Identity {identity_id} does not meet quarantine thresholds (score {risk_score}, level {risk_level})."
        snapshot = _snapshot_state(identity_id, conn)
        ts = _get_timestamp()
        conn.execute("INSERT INTO quarantine_records (identity_id, timestamp, pre_quarantine_state, status) VALUES (?,?,?,?)",
                     (identity_id, ts, snapshot, 'quarantined'))
        conn.execute("UPDATE ad_accounts SET status = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        conn.execute("UPDATE aws_accounts SET policy = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        conn.execute("UPDATE okta_accounts SET status = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        conn.execute("DELETE FROM api_tokens WHERE identity_id = ?", (identity_id,))
        conn.execute("UPDATE ad_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'", (identity_id,))
        conn.execute("UPDATE aws_accounts SET policy = NULL WHERE identity_id = ? AND policy LIKE '%Admin%'", (identity_id,))
        conn.execute("UPDATE okta_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'", (identity_id,))
        conn.commit()
        return f"Identity {identity_id} successfully quarantined."
    finally:
        conn.close()


def release_identity(identity_id: str) -> str:
    """Release a quarantined identity, restoring its previous state."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rec = conn.execute("SELECT * FROM quarantine_records WHERE identity_id = ? ORDER BY id DESC LIMIT 1",
                           (identity_id,)).fetchone()
        if not rec:
            return f"No quarantine record for {identity_id}."
        if rec['pre_quarantine_state']:
            snapshot = json.loads(rec['pre_quarantine_state'])
            if snapshot.get('ad'):
                cols = ','.join([f"{k} = ?" for k in snapshot['ad'] if k != 'identity_id'])
                vals = [v for k, v in snapshot['ad'].items() if k != 'identity_id']
                conn.execute(f"UPDATE ad_accounts SET {cols} WHERE identity_id = ?", (*vals, identity_id))
            if snapshot.get('aws'):
                cols = ','.join([f"{k} = ?" for k in snapshot['aws'] if k != 'identity_id'])
                vals = [v for k, v in snapshot['aws'].items() if k != 'identity_id']
                conn.execute(f"UPDATE aws_accounts SET {cols} WHERE identity_id = ?", (*vals, identity_id))
            if snapshot.get('okta'):
                cols = ','.join([f"{k} = ?" for k in snapshot['okta'] if k != 'identity_id'])
                vals = [v for k, v in snapshot['okta'].items() if k != 'identity_id']
                conn.execute(f"UPDATE okta_accounts SET {cols} WHERE identity_id = ?", (*vals, identity_id))
            for token in snapshot.get('tokens', []):
                cols = ','.join(token.keys())
                placeholders = ','.join(['?'] * len(token))
                conn.execute(f"INSERT INTO api_tokens ({cols}) VALUES ({placeholders})", tuple(token.values()))
        conn.execute("UPDATE quarantine_records SET status = 'released' WHERE id = ?", (rec['id'],))
        conn.commit()
        return f"Identity {identity_id} released and state restored."
    finally:
        conn.close()
