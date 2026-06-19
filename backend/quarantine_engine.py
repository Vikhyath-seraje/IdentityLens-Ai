import sqlite3
import json
import datetime
import uuid

from backend.risk_engine import RiskEngine
from backend.anomaly_detection import AnomalyDetectionEngine
from backend.privilege_analyzer import PrivilegeAnalyzer
from database.init_db import ensure_quarantine_schema

DB_PATH = 'database/identitylens.db'


def _get_timestamp():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def _connect():
    """Open a connection with row factory and ensure the quarantine schema exists."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_quarantine_schema(conn)
    return conn


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


def check_quarantine_rules(identity_id: str) -> dict:
    """Evaluate quarantine policy rules for a given identity."""
    conn = _connect()
    try:
        engine = RiskEngine()
        df = engine.calculate_risk_scores()
        row = df[df['identity_id'] == identity_id]
        if row.empty:
            return {"eligible": False, "rules": [], "score": 0, "level": "Low"}

        risk_score = int(row['risk_score'].iloc[0])
        risk_level = row['risk_level'].iloc[0]

        anomaly_engine = AnomalyDetectionEngine()
        anomalies_df = anomaly_engine.detect_anomalies()
        user_anomalies = anomalies_df[anomalies_df['identity_id'] == identity_id]['anomaly_type'].tolist()

        matched_rules = []
        if risk_score > 75:
            matched_rules.append("Risk Score > 75")
        if risk_level == 'Critical':
            matched_rules.append("Risk Level = Critical")
        if 'Offboarding Gap' in user_anomalies:
            matched_rules.append("OFFBOARDING_GAP")
        if 'Cross Platform Admin' in user_anomalies:
            matched_rules.append("CROSS_PLATFORM_ADMIN")
        if 'Old API Token' in user_anomalies:
            matched_rules.append("TOKEN_ABUSE")
        if 'Service Account Abuse' in user_anomalies:
            matched_rules.append("SERVICE_ACCOUNT_ABUSE")

        return {
            "eligible": len(matched_rules) > 0,
            "rules": matched_rules,
            "score": risk_score,
            "level": risk_level
        }
    finally:
        conn.close()


# ── Atomic remediation steps ────────────────────────────────────────────────

def revoke_tokens(identity_id: str, conn) -> int:
    """Delete all API tokens for the identity. Returns the number revoked."""
    count = conn.execute(
        "SELECT COUNT(*) FROM api_tokens WHERE identity_id = ?", (identity_id,)
    ).fetchone()[0]
    conn.execute("DELETE FROM api_tokens WHERE identity_id = ?", (identity_id,))
    return count


def remove_admin_privileges(identity_id: str, conn) -> int:
    """Null admin roles/policies across AD, AWS and Okta. Returns the number removed."""
    removed = 0

    ad_admin = conn.execute(
        "SELECT role FROM ad_accounts WHERE identity_id = ? AND role LIKE '%Admin%'",
        (identity_id,)
    ).fetchone()
    if ad_admin:
        conn.execute(
            "UPDATE ad_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'",
            (identity_id,)
        )
        removed += 1

    aws_admin = conn.execute(
        "SELECT policy FROM aws_accounts WHERE identity_id = ? AND policy LIKE '%Admin%'",
        (identity_id,)
    ).fetchone()
    if aws_admin:
        conn.execute(
            "UPDATE aws_accounts SET policy = NULL WHERE identity_id = ? AND policy LIKE '%Admin%'",
            (identity_id,)
        )
        removed += 1

    okta_admin = conn.execute(
        "SELECT role FROM okta_accounts WHERE identity_id = ? AND role LIKE '%Admin%'",
        (identity_id,)
    ).fetchone()
    if okta_admin:
        conn.execute(
            "UPDATE okta_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'",
            (identity_id,)
        )
        removed += 1

    return removed


def generate_quarantine_audit(identity_id: str, events, conn, run_id: str) -> None:
    """Bulk-insert audit events for a quarantine/release run.

    events: list of dicts with keys {action, platform (optional), detail (optional)}.
    """
    ts = _get_timestamp()
    rows = [(
        ts,
        identity_id,
        ev['action'],
        ev.get('platform'),
        ev.get('detail'),
        run_id,
    ) for ev in events]
    conn.executemany(
        "INSERT INTO quarantine_audit_events "
        "(timestamp, identity_id, action, platform, detail, run_id) VALUES (?,?,?,?,?,?)",
        rows
    )


# ── Risk recalculation ──────────────────────────────────────────────────────

def _score_for_identity(identity_id: str) -> tuple:
    """Recompute the RiskEngine score for a single identity against the current DB state.

    Mirrors RiskEngine.calculate_risk_scores so before/after numbers are comparable.
    Returns (score, level, anomaly_count, privilege_count).
    """
    anomaly_counts = (
        AnomalyDetectionEngine()
        .detect_anomalies()
        .groupby('identity_id')
        .size()
        .to_dict()
    )
    priv_count = len(PrivilegeAnalyzer().get_effective_privileges(identity_id))

    num_anomalies = anomaly_counts.get(identity_id, 0)
    score = min(10 + num_anomalies * 15 + priv_count * 5, 100)
    if score <= 25:
        level = 'Low'
    elif score <= 50:
        level = 'Medium'
    elif score <= 75:
        level = 'High'
    else:
        level = 'Critical'
    return score, level, num_anomalies, priv_count


def calculate_post_quarantine_risk(identity_id: str, conn, run_id: str, pre: dict) -> dict:
    """Recalculate the identity's risk after quarantine and emit an audit event.

    pre: {'score', 'level'} captured before mutation.
    """
    post_score, post_level, post_anom, post_priv = _score_for_identity(identity_id)
    generate_quarantine_audit(identity_id, [{
        'action': 'RISK_RECALCULATED',
        'detail': f"pre={pre['score']}/{pre['level']} -> post={post_score}/{post_level} "
                  f"(anomalies={post_anom}, privileges={post_priv})",
    }], conn, run_id)
    return {
        'pre_score': pre['score'],
        'pre_level': pre['level'],
        'post_score': int(post_score),
        'post_level': post_level,
    }


# ── Orchestration ───────────────────────────────────────────────────────────

def quarantine_identity(identity_id: str, force: bool = False) -> str:
    """Quarantine an identity across all platforms following the full workflow."""
    conn = _connect()
    try:
        rules_check = check_quarantine_rules(identity_id)
        if not rules_check['eligible'] and not force:
            return f"Identity {identity_id} does not meet quarantine thresholds."

        pre = {'score': rules_check['score'], 'level': rules_check['level']}
        run_id = str(uuid.uuid4())
        snapshot = _snapshot_state(identity_id, conn)
        ts = _get_timestamp()
        events = []

        # Steps 1-3: Quarantine AD / AWS / Okta accounts
        conn.execute("UPDATE ad_accounts SET status = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        conn.execute("UPDATE aws_accounts SET status = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        conn.execute("UPDATE okta_accounts SET status = 'Quarantined' WHERE identity_id = ?", (identity_id,))
        events.append({'action': 'QUARANTINE_AD', 'platform': 'Active Directory'})
        events.append({'action': 'QUARANTINE_AWS', 'platform': 'AWS IAM'})
        events.append({'action': 'QUARANTINE_OKTA', 'platform': 'Okta'})

        # Step 4: Revoke API tokens
        tokens_revoked = revoke_tokens(identity_id, conn)
        events.append({
            'action': 'TOKEN_REVOKED',
            'platform': 'API',
            'detail': f"revoked {tokens_revoked} token(s)",
        })

        # Step 5: Remove admin privileges
        privileges_removed = remove_admin_privileges(identity_id, conn)
        events.append({
            'action': 'PRIVILEGE_REMOVED',
            'detail': f"removed {privileges_removed} admin privilege(s)",
        })

        # Step 6: Generate audit events
        events.append({
            'action': 'FORCE_QUARANTINE' if force and not rules_check['eligible'] else 'QUARANTINE',
            'detail': '; '.join(rules_check['rules']) if rules_check['rules'] else 'manual override',
        })
        generate_quarantine_audit(identity_id, events, conn, run_id)
        # Commit the account mutations + audit events so the risk recalculation
        # (which opens its own read-only connections) sees the neutralized state.
        conn.commit()

        # Step 7: Recalculate risk (writes its own audit event)
        risk = calculate_post_quarantine_risk(identity_id, conn, run_id, pre)

        conn.execute(
            "INSERT INTO quarantine_records "
            "(identity_id, timestamp, pre_quarantine_state, status, "
            " pre_risk_score, pre_risk_level, post_risk_score, post_risk_level, "
            " tokens_revoked, privileges_removed) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (identity_id, ts, snapshot, 'quarantined',
             risk['pre_score'], risk['pre_level'],
             risk['post_score'], risk['post_level'],
             tokens_revoked, privileges_removed)
        )
        conn.commit()
        return (f"Identity {identity_id} quarantined. "
                f"Risk {risk['pre_score']}/{pre['level']} -> {risk['post_score']}/{risk['post_level']}, "
                f"tokens revoked: {tokens_revoked}, privileges removed: {privileges_removed}.")
    finally:
        conn.close()


def release_identity(identity_id: str) -> str:
    """Release a quarantined identity, restoring its previous state."""
    conn = _connect()
    try:
        rec = conn.execute(
            "SELECT * FROM quarantine_records WHERE identity_id = ? ORDER BY id DESC LIMIT 1",
            (identity_id,)
        ).fetchone()
        if not rec:
            return f"No quarantine record for {identity_id}."

        run_id = str(uuid.uuid4())
        if rec['pre_quarantine_state']:
            snapshot = json.loads(rec['pre_quarantine_state'])
            for tbl, key in [('ad_accounts', 'ad'), ('aws_accounts', 'aws'), ('okta_accounts', 'okta')]:
                row = snapshot.get(key)
                if row:
                    cols = [k for k in row.keys() if k != 'identity_id']
                    if cols:
                        assignments = ', '.join([f"{k} = ?" for k in cols])
                        vals = [row[k] for k in cols]
                        conn.execute(
                            f"UPDATE {tbl} SET {assignments} WHERE identity_id = ?",
                            (*vals, identity_id)
                        )
            for token in snapshot.get('tokens', []):
                cols = list(token.keys())
                placeholders = ', '.join(['?'] * len(token))
                collist = ', '.join(cols)
                conn.execute(
                    f"INSERT INTO api_tokens ({collist}) VALUES ({placeholders})",
                    tuple(token.values())
                )

        conn.execute(
            "UPDATE quarantine_records SET status = 'released' WHERE id = ?", (rec['id'],)
        )
        generate_quarantine_audit(identity_id, [{'action': 'RELEASE'}], conn, run_id)
        conn.commit()
        return f"Identity {identity_id} released and state restored."
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        action, ident = sys.argv[1], sys.argv[2]
        if action == 'quarantine':
            print(quarantine_identity(ident))
        elif action == 'force':
            print(quarantine_identity(ident, force=True))
        elif action == 'release':
            print(release_identity(ident))
