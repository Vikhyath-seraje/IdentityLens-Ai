import sqlite3
import pandas as pd
from backend.identity_resolver import IdentityResolver
from backend.anomaly_detection import AnomalyDetectionEngine
from backend.risk_engine import RiskEngine


class ValidationEngine:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path
        self.resolver = IdentityResolver(db_path)
        self.anomaly_engine = AnomalyDetectionEngine(db_path)
        self.risk_engine = RiskEngine(db_path)
        self._ensure_schema()

    def _ensure_schema(self):
        """Ensures the database schema has all required columns that might be missing on deployed versions with persistent stale DB files."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if expires_at exists in ad_accounts
        c.execute("PRAGMA table_info(ad_accounts)")
        columns = [info[1] for info in c.fetchall()]
        if 'expires_at' not in columns:
            try:
                c.execute("ALTER TABLE ad_accounts ADD COLUMN expires_at TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                pass
                
        # Ensure identity_groups exists
        try:
            c.execute("CREATE TABLE IF NOT EXISTS identity_groups (identity_id TEXT, group_name TEXT)")
            conn.commit()
        except sqlite3.OperationalError:
                pass
                
        conn.close()

    def inject_scenarios(self):
        """Injects test records directly into the SQLite database."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        c = conn.cursor()

        # Clear previous test data
        test_ids = "('TC001', 'TC002', 'TC003', 'TC004', 'TC005', 'TC006', 'TC007', 'TC008', 'TC009')"
        c.execute(f"DELETE FROM identities WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM ad_accounts WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM aws_accounts WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM okta_accounts WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM offboarding_records WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM api_tokens WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM identity_groups WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM audit_logs WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM change_requests WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM resource_access_logs WHERE identity_id IN {test_ids}")
        c.execute(f"DELETE FROM identity_baselines WHERE identity_id IN {test_ids}")
        # NOTE: SQLite uses double-quotes for reserved-word identifiers, NOT backticks
        c.execute('DELETE FROM group_memberships WHERE "group" IN (\'svc-etl-prod\', \'ServiceAccounts\', \'ITAdmins\')')

        # TC001 - Offboarding Gap
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC001', 'Test Contractor', 'Human')")
        c.execute("INSERT INTO offboarding_records (identity_id, termination_date) VALUES ('TC001', '2024-01-01')")
        c.execute("INSERT INTO ad_accounts (identity_id, status) VALUES ('TC001', 'Disabled')")
        c.execute("INSERT INTO aws_accounts (identity_id, status) VALUES ('TC001', 'Active')")
        c.execute("INSERT INTO okta_accounts (identity_id, status) VALUES ('TC001', 'Suspended')")

        # TC002 - Nested Privilege Escalation (svc-etl-prod -> ServiceAccounts -> ITAdmins -> GlobalAdmins)
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC002', 'svc-etl-prod', 'Service Account')")
        c.execute("INSERT INTO identity_groups (identity_id, group_name) VALUES ('TC002', 'svc-etl-prod')")
        c.execute('INSERT OR IGNORE INTO group_memberships ("group", parent_group) VALUES (\'svc-etl-prod\', \'ServiceAccounts\')')
        c.execute('INSERT OR IGNORE INTO group_memberships ("group", parent_group) VALUES (\'ServiceAccounts\', \'ITAdmins\')')
        c.execute('INSERT OR IGNORE INTO group_memberships ("group", parent_group) VALUES (\'ITAdmins\', \'GlobalAdmins\')')

        # TC003 - Token Abuse (400 days old token)
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC003', 'Test Token User', 'Human')")
        c.execute("INSERT INTO api_tokens (token_id, identity_id, age_days) VALUES ('tok_tc003', 'TC003', 400)")

        # TC004 - Expired Admin Exception
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC004', 'Test Temp Admin', 'Human')")
        c.execute("INSERT INTO ad_accounts (identity_id, ad_user, status, expires_at) VALUES ('TC004', 'temp_admin', 'Active', '2020-01-01')")

        # TC005 - Dormant Cross Platform Admin
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC005', 'Test Dormant Admin', 'Human')")
        c.execute("INSERT INTO ad_accounts (identity_id, status, role, last_login) VALUES ('TC005', 'Active', 'Domain Admin', '2021-01-01')")
        c.execute("INSERT INTO aws_accounts (identity_id, status, policy, last_login) VALUES ('TC005', 'Active', 'AWS Administrator', '2021-01-01')")
        c.execute("INSERT INTO okta_accounts (identity_id, status, role, last_login) VALUES ('TC005', 'Active', 'SuperAdmin', '2021-01-01')")

        # ── ITDR Test Cases ─────────────────────────────────────────────────────────

        # TC006 - UNAUTHORIZED_PRIVILEGE_ESCALATION
        # PrivilegedServiceAccount + self-assigned PrivilegeEscalation + rejected change ticket
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC006', 'svc-unauth-esc', 'PrivilegedServiceAccount')")
        c.execute("INSERT INTO ad_accounts (identity_id, ad_user, status, role) VALUES ('TC006', 'svc-unauth-esc', 'Active', 'Domain Admin')")
        c.execute("INSERT INTO audit_logs (identity_id, action, detail) VALUES ('TC006', 'RoleAssigned', 'Self-assigned Domain Admin')")
        c.execute("INSERT INTO change_requests (ticket_id, identity_id, change_type, approved, approved_by, approval_date) VALUES ('CR_T006', 'TC006', 'PrivilegeEscalation', 0, '', '')")

        # TC007 - SERVICE_ACCOUNT_COMPROMISE (no ticket at all)
        # ServiceAccount + PrivilegeEscalation audit + first-time sensitive access + outside hours
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC007', 'svc-compromised', 'ServiceAccount')")
        c.execute("INSERT INTO ad_accounts (identity_id, ad_user, status) VALUES ('TC007', 'svc-compromised', 'Active')")
        c.execute("INSERT INTO okta_accounts (identity_id, status, last_login) VALUES ('TC007', 'Active', '2024-12-15')")
        c.execute("INSERT INTO audit_logs (identity_id, action, detail) VALUES ('TC007', 'RoleAssigned', 'Self-assigned Admin')")
        # No change_requests ticket for TC007
        c.execute("INSERT INTO resource_access_logs (timestamp, identity_id, resource, action) VALUES ('2024-12-15 03:30:00', 'TC007', 'production-secrets', 'READ')")
        c.execute("INSERT INTO identity_baselines (identity_id, start_hour, end_hour) VALUES ('TC007', 8, 16)")

        # TC008 - FIRST_TIME_SENSITIVE_ACCESS
        # ServiceAccount + first-time access to hr_database.salaries
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC008', 'svc-data-reader', 'ServiceAccount')")
        c.execute("INSERT INTO ad_accounts (identity_id, ad_user, status) VALUES ('TC008', 'svc-data-reader', 'Active')")
        c.execute("INSERT INTO resource_access_logs (timestamp, identity_id, resource, action) VALUES ('2024-12-15 10:00:00', 'TC008', 'hr_database.salaries', 'READ')")
        c.execute("INSERT INTO identity_baselines (identity_id, start_hour, end_hour) VALUES ('TC008', 6, 14)")

        # TC009 - OUTSIDE_NORMAL_ACTIVITY_WINDOW
        # Employee with baseline 08-18, activity at 02:30
        c.execute("INSERT INTO identities (identity_id, name, type) VALUES ('TC009', 'Test Night Owl', 'Employee')")
        c.execute("INSERT INTO ad_accounts (identity_id, ad_user, status) VALUES ('TC009', 'night_owl', 'Active')")
        c.execute("INSERT INTO resource_access_logs (timestamp, identity_id, resource, action) VALUES ('2024-12-15 02:30:00', 'TC009', 'ad_users', 'READ')")
        c.execute("INSERT INTO identity_baselines (identity_id, start_hour, end_hour) VALUES ('TC009', 8, 18)")

        conn.commit()
        conn.close()

    def run_validations(self):
        # 1. Inject data
        self.inject_scenarios()

        # 2. Run backend systems
        self.resolver.get_identity_summary()  # Force identity load
        anomalies_df = self.anomaly_engine.detect_anomalies()
        risk_df = self.risk_engine.calculate_risk_scores()

        results = []

        # Validate TC001 — OFFBOARDING_GAP
        tc001_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC001']['anomaly_type'].tolist()
        tc001_risk = risk_df[risk_df['identity_id'] == 'TC001']
        tc001_score = tc001_risk.iloc[0]['risk_score'] if not tc001_risk.empty else 0
        tc001_level = tc001_risk.iloc[0]['risk_level'] if not tc001_risk.empty else 'N/A'
        tc001_pass = 'Offboarding Gap' in tc001_anoms and tc001_score >= 15
        results.append({
            'name': 'TC001_Offboarding_Gap',
            'status': 'PASS' if tc001_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc001_anoms or ['(none)']}<br>"
                f"Risk Score: {tc001_score} | Risk Level: {tc001_level}<br>"
                f"Expected: OFFBOARDING_GAP detected, score elevated"
            )
        })

        # Validate TC002 — NESTED_ESCALATION
        tc002_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC002']['anomaly_type'].tolist()
        tc002_pass = 'Nested Escalation' in tc002_anoms
        results.append({
            'name': 'TC002_Nested_Privilege_Escalation',
            'status': 'PASS' if tc002_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc002_anoms or ['(none)']}<br>"
                f"Attack chain: svc-etl-prod &#8594; ServiceAccounts &#8594; ITAdmins &#8594; GlobalAdmins<br>"
                f"Expected: NESTED_ESCALATION detected"
                f"<div style='margin-top:10px;font-family:monospace;font-size:0.82rem;"
                f"background:#f4f6f8;padding:10px 14px;border-radius:6px;"
                f"border:1px solid #ddd;line-height:1.8;'>"
                f"<span style='color:#E60028;font-weight:700;'>&#9656; Attack Graph</span><br>"
                f"svc-etl-prod<br>"
                f"&nbsp;&nbsp;&#8627; ServiceAccounts<br>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;&#8627; ITAdmins<br>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&#8627; <span style='color:#E60028;font-weight:700;'>GlobalAdmins</span>"
                f"</div>"
            )
        })

        # Validate TC003 — TOKEN_ABUSE (400-day token)
        tc003_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC003']['anomaly_type'].tolist()
        tc003_risk = risk_df[risk_df['identity_id'] == 'TC003']
        tc003_score = tc003_risk.iloc[0]['risk_score'] if not tc003_risk.empty else 0
        tc003_pass = 'Token Abuse' in tc003_anoms and tc003_score >= 15
        results.append({
            'name': 'TC003_Expired_Token',
            'status': 'PASS' if tc003_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc003_anoms or ['(none)']}<br>"
                f"Token age: 400 days | Risk Score: {tc003_score}<br>"
                f"Expected: TOKEN_ABUSE detected, score elevated"
            )
        })

        # Validate TC004 — EXPIRED_ADMIN_PRIVILEGE
        tc004_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC004']['anomaly_type'].tolist()
        tc004_pass = 'Expired Privilege' in tc004_anoms
        results.append({
            'name': 'TC004_Expired_Admin_Exception',
            'status': 'PASS' if tc004_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc004_anoms or ['(none)']}<br>"
                f"Account: temp_admin | Expiry: 2020-01-01 | Status: Active<br>"
                f"Expected: EXPIRED_PRIVILEGE detected"
            )
        })

        # Validate TC005 — DORMANT CROSS-PLATFORM ADMIN
        tc005_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC005']['anomaly_type'].tolist()
        tc005_pass = 'Cross Platform Admin' in tc005_anoms and 'Dormant Admin' in tc005_anoms
        results.append({
            'name': 'TC005_Dormant_Cross_Platform_Admin',
            'status': 'PASS' if tc005_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc005_anoms or ['(none)']}<br>"
                f"Platforms: AD (Domain Admin), AWS (AWS Administrator), Okta (SuperAdmin)<br>"
                f"Expected: CROSS_PLATFORM_ADMIN + DORMANT_ADMIN detected"
            )
        })

        # ══════════════════════════════════════════════════════
        # ITDR VALIDATIONS (TC006 - TC009)
        # ══════════════════════════════════════════════════════

        # Validate TC006 — UNAUTHORIZED_PRIVILEGE_ESCALATION
        tc006_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC006']['anomaly_type'].tolist()
        tc006_risk = risk_df[risk_df['identity_id'] == 'TC006']
        tc006_score = tc006_risk.iloc[0]['risk_score'] if not tc006_risk.empty else 0
        tc006_pass = 'UNAUTHORIZED_PRIVILEGE_ESCALATION' in tc006_anoms and tc006_score >= 30
        results.append({
            'name': 'TC006_Unauthorized_Privilege_Escalation',
            'status': 'PASS' if tc006_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc006_anoms or ['(none)']}<br>"
                f"Type: PrivilegedServiceAccount | Risk Score: {tc006_score}<br>"
                f"Expected: UNAUTHORIZED_PRIVILEGE_ESCALATION detected (SA + rejected ticket)"
            )
        })

        # Validate TC007 — SERVICE_ACCOUNT_COMPROMISE (composite)
        tc007_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC007']['anomaly_type'].tolist()
        tc007_risk = risk_df[risk_df['identity_id'] == 'TC007']
        tc007_score = tc007_risk.iloc[0]['risk_score'] if not tc007_risk.empty else 0
        tc007_pass = 'SERVICE_ACCOUNT_COMPROMISE' in tc007_anoms and tc007_score >= 50
        results.append({
            'name': 'TC007_Service_Account_Compromise',
            'status': 'PASS' if tc007_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc007_anoms or ['(none)']}<br>"
                f"Type: ServiceAccount | Risk Score: {tc007_score}<br>"
                f"Expected: SERVICE_ACCOUNT_COMPROMISE (composite: no ticket + sensitive access + off-hours)"
            )
        })

        # Validate TC008 — FIRST_TIME_SENSITIVE_ACCESS
        tc008_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC008']['anomaly_type'].tolist()
        tc008_risk = risk_df[risk_df['identity_id'] == 'TC008']
        tc008_score = tc008_risk.iloc[0]['risk_score'] if not tc008_risk.empty else 0
        tc008_pass = 'FIRST_TIME_SENSITIVE_ACCESS' in tc008_anoms and tc008_score >= 15
        results.append({
            'name': 'TC008_First_Time_Sensitive_Access',
            'status': 'PASS' if tc008_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc008_anoms or ['(none)']}<br>"
                f"Type: ServiceAccount | Risk Score: {tc008_score}<br>"
                f"Expected: FIRST_TIME_SENSITIVE_ACCESS (first access to hr_database.salaries)"
            )
        })

        # Validate TC009 — OUTSIDE_NORMAL_ACTIVITY_WINDOW
        tc009_anoms = anomalies_df[anomalies_df['identity_id'] == 'TC009']['anomaly_type'].tolist()
        tc009_risk = risk_df[risk_df['identity_id'] == 'TC009']
        tc009_score = tc009_risk.iloc[0]['risk_score'] if not tc009_risk.empty else 0
        tc009_pass = 'OUTSIDE_NORMAL_ACTIVITY_WINDOW' in tc009_anoms and tc009_score >= 15
        results.append({
            'name': 'TC009_Outside_Normal_Activity_Window',
            'status': 'PASS' if tc009_pass else 'FAIL',
            'details': (
                f"Detected anomalies: {tc009_anoms or ['(none)']}<br>"
                f"Type: Employee | Baseline: 08-18 | Activity: 02:30 | Risk Score: {tc009_score}<br>"
                f"Expected: OUTSIDE_NORMAL_ACTIVITY_WINDOW detected"
            )
        })

        return results
