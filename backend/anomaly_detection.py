import sqlite3
import pandas as pd

# ── MITRE ATT&CK Mapping ───────────────────────────────────────────────────────────
MITRE_MAPPING = {
    'Offboarding Gap':            {'technique': 'T1098', 'tactic': 'Persistence',        'name': 'Account Manipulation'},
    'Token Abuse':                {'technique': 'T1552', 'tactic': 'Credential Access',   'name': 'Unsecured Credentials'},
    'Old API Token':             {'technique': 'T1552', 'tactic': 'Credential Access',   'name': 'Unsecured Credentials'},
    'Cross Platform Admin':       {'technique': 'T1078', 'tactic': 'Initial Access',      'name': 'Valid Accounts'},
    'Dormant Admin':             {'technique': 'T1021', 'tactic': 'Lateral Movement',    'name': 'Remote Services'},
    'Service Account Abuse':     {'technique': 'T1078.004', 'tactic': 'Initial Access',   'name': 'Valid Accounts: Cloud Accounts'},
    'Nested Escalation':         {'technique': 'T1078', 'tactic': 'Privilege Escalation','name': 'Valid Accounts'},
    'Expired Privilege':         {'technique': 'T1098', 'tactic': 'Persistence',        'name': 'Account Manipulation'},
    'Privilege Escalation':      {'technique': 'T1548', 'tactic': 'Privilege Escalation','name': 'Abuse Elevation Control Mechanism'},
    'Orphan Contractor':         {'technique': 'T1133', 'tactic': 'Initial Access',      'name': 'External Remote Services'},
    'Impossible Travel':         {'technique': 'T1078', 'tactic': 'Initial Access',      'name': 'Valid Accounts'},
    'Credential Sharing':        {'technique': 'T1110', 'tactic': 'Credential Access',  'name': 'Brute Force'},
    'UNAUTHORIZED_PRIVILEGE_ESCALATION': {'technique': 'T1548', 'tactic': 'Privilege Escalation', 'name': 'Abuse Elevation Control Mechanism'},
    'FIRST_TIME_SENSITIVE_ACCESS':     {'technique': 'T1213', 'tactic': 'Collection',  'name': 'Data from Information Repositories'},
    'OUTSIDE_NORMAL_ACTIVITY_WINDOW':   {'technique': 'T1021', 'tactic': 'Lateral Movement', 'name': 'Remote Services'},
    'SERVICE_ACCOUNT_COMPROMISE':       {'technique': 'T1078.004', 'tactic': 'Initial Access', 'name': 'Valid Accounts: Cloud Accounts'},
}

def get_mitre_mapping(anomaly_type):
    """Return MITRE ATT&CK mapping dict for a given anomaly type."""
    return MITRE_MAPPING.get(anomaly_type, {
        'technique': 'N/A', 'tactic': 'N/A', 'name': 'N/A'
    })

# ── High-sensitivity resources for ITDR Rule 13 ────────────────────────────────────
HIGH_SENSITIVITY_RESOURCES = {
    'hr_database.salaries', 'financial-records', 'customer-data',
    'production-secrets', 'source-code'
}


class AnomalyDetectionEngine:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path

    def detect_anomalies(self):
        """
        Runs rule-based anomaly detection across the dataset.
        Returns a DataFrame with [identity_id, anomaly_type, description].
        """
        conn = sqlite3.connect(self.db_path)
        anomalies = []

        # 1. Offboarding Gap: Terminated users with active accounts
        query_offboarding = """
        SELECT o.identity_id, o.termination_date, ad.status AS ad_status, aws.status AS aws_status, okta.status AS okta_status
        FROM offboarding_records o
        LEFT JOIN ad_accounts ad ON o.identity_id = ad.identity_id
        LEFT JOIN aws_accounts aws ON o.identity_id = aws.identity_id
        LEFT JOIN okta_accounts okta ON o.identity_id = okta.identity_id
        WHERE ad.status = 'Active' OR aws.status = 'Active' OR okta.status = 'Active'
        """
        offboarded_active = pd.read_sql_query(query_offboarding, conn)
        for _, row in offboarded_active.iterrows():
            anomalies.append({
                'identity_id': row['identity_id'],
                'anomaly_type': 'Offboarding Gap',
                'description': f"User terminated on {row['termination_date']} but has active accounts."
            })

        # 2. Old API Token / Token Abuse
        query_tokens = "SELECT identity_id, age_days FROM api_tokens WHERE age_days > 90"
        old_tokens = pd.read_sql_query(query_tokens, conn)
        for _, row in old_tokens.iterrows():
            anomaly_type = 'Token Abuse' if row['age_days'] >= 365 else 'Old API Token'
            anomalies.append({
                'identity_id': row['identity_id'],
                'anomaly_type': anomaly_type,
                'description': f"API token is {row['age_days']} days old (limit 90)."
            })

        # 3. Cross Platform Admin: Admin in AD and AWS/Okta
        query_cross_admin = """
        SELECT i.identity_id, ad.role AS ad_role, aws.policy AS aws_policy, okta.role AS okta_role
        FROM identities i
        LEFT JOIN ad_accounts ad ON i.identity_id = ad.identity_id
        LEFT JOIN aws_accounts aws ON i.identity_id = aws.identity_id
        LEFT JOIN okta_accounts okta ON i.identity_id = okta.identity_id
        """
        roles_df = pd.read_sql_query(query_cross_admin, conn)
        for _, row in roles_df.iterrows():
            admin_count = 0
            if pd.notna(row['ad_role']) and 'Admin' in row['ad_role']: admin_count += 1
            if pd.notna(row['aws_policy']) and 'Admin' in row['aws_policy']: admin_count += 1
            if pd.notna(row['okta_role']) and 'Admin' in row['okta_role']: admin_count += 1
            
            if admin_count >= 2:
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Cross Platform Admin',
                    'description': f"Identity holds Admin privileges across {admin_count} platforms."
                })

        # 4. Dormant Admin: Admin role but no recent login (simplified check)
        query_dormant = """
        SELECT identity_id, ad_user, role, last_login FROM ad_accounts WHERE role LIKE '%Admin%' AND status = 'Active'
        """
        ad_admins = pd.read_sql_query(query_dormant, conn)
        for _, row in ad_admins.iterrows():
            if pd.isna(row['last_login']) or row['last_login'] < '2023-01-01':
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Dormant Admin',
                    'description': f"AD Admin account dormant. Last login: {row['last_login']}."
                })
                
        # 5. Service Account Abuse: Service account with interactive Okta login
        query_svc = """
        SELECT i.identity_id, okta.last_login
        FROM identities i
        JOIN okta_accounts okta ON i.identity_id = okta.identity_id
        WHERE i.type IN ('ServiceAccount', 'PrivilegedServiceAccount') AND okta.last_login IS NOT NULL
        """
        svc_abuse = pd.read_sql_query(query_svc, conn)
        for _, row in svc_abuse.iterrows():
            anomalies.append({
                'identity_id': row['identity_id'],
                'anomaly_type': 'Service Account Abuse',
                'description': f"Service account has an Okta interactive login record."
            })

        # 6. Nested Privilege Escalation
        query_nested = """
        WITH RECURSIVE group_tree AS (
            SELECT identity_id, group_name AS current_group
            FROM identity_groups
            UNION ALL
            SELECT t.identity_id, m.parent_group
            FROM group_tree t
            JOIN group_memberships m ON t.current_group = m."group"
            WHERE m.parent_group IS NOT NULL
        )
        SELECT DISTINCT identity_id
        FROM group_tree
        WHERE current_group = 'GlobalAdmins'
        """
        try:
            nested_df = pd.read_sql_query(query_nested, conn)
            for _, row in nested_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Nested Escalation',
                    'description': f"Identity inherits GlobalAdmins privileges via nested groups."
                })
        except Exception:
            pass

        # 7. Expired Privilege Exception
        query_expired = """
        SELECT identity_id, ad_user, expires_at 
        FROM ad_accounts 
        WHERE expires_at IS NOT NULL 
        AND expires_at < date('now') 
        AND status = 'Active'
        """
        try:
            expired_df = pd.read_sql_query(query_expired, conn)
            for _, row in expired_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Expired Privilege',
                    'description': f"Active account {row['ad_user']} past expiration date: {row['expires_at']}."
                })
        except Exception:
            pass

        # 8. Privilege Escalation (Self-assigned admin)
        query_priv_esc = """
        SELECT identity_id FROM audit_logs 
        WHERE action = 'RoleAssigned' AND detail LIKE '%Self-assigned%'
        """
        try:
            priv_df = pd.read_sql_query(query_priv_esc, conn)
            for _, row in priv_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Privilege Escalation',
                    'description': "Audit logs show unauthorized self-assignment of high privileges."
                })
        except Exception:
            pass

        # 9. Orphan Contractor (Contractor with no manager)
        query_orphan = """
        SELECT i.identity_id 
        FROM identities i
        LEFT JOIN hr_records hr ON i.identity_id = hr.identity_id
        WHERE i.type = 'Contractor' AND (hr.manager_id IS NULL OR hr.manager_id = '')
        """
        try:
            orphan_df = pd.read_sql_query(query_orphan, conn)
            for _, row in orphan_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Orphan Contractor',
                    'description': "Contractor account is active but lacks an assigned manager in HR records."
                })
        except Exception:
            pass

        # 10. Impossible Travel
        query_travel = """
        SELECT identity_id FROM audit_logs 
        WHERE action = 'Login' AND detail LIKE '%Impossible Travel%'
        """
        try:
            travel_df = pd.read_sql_query(query_travel, conn)
            for _, row in travel_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Impossible Travel',
                    'description': "Concurrent logins detected from geographically distant IP addresses."
                })
        except Exception:
            pass

        # 11. Credential Sharing
        query_cred = """
        SELECT identity_id FROM audit_logs 
        WHERE action = 'Login' AND detail LIKE '%Credential Sharing%'
        """
        try:
            cred_df = pd.read_sql_query(query_cred, conn)
            for _, row in cred_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'Credential Sharing',
                    'description': "Simultaneous sessions established from 5+ distinct IP addresses."
                })
        except Exception:
            pass

        # ══════════════════════════════════════════════════════
        # ITDR RULES 12-15
        # ══════════════════════════════════════════════════════

        # 12. UNAUTHORIZED_PRIVILEGE_ESCALATION: Service Account + PrivilegeEscalation without approved ticket
        try:
            query_unauth_esc = """
            SELECT DISTINCT al.identity_id, al.detail
            FROM audit_logs al
            JOIN identities i ON al.identity_id = i.identity_id
            WHERE al.action = 'RoleAssigned' AND al.detail LIKE '%Self-assigned%'
            AND i.type IN ('ServiceAccount', 'PrivilegedServiceAccount')
            AND al.identity_id NOT IN (
                SELECT cr.identity_id FROM change_requests cr
                WHERE cr.change_type = 'PrivilegeEscalation' AND cr.approved = 1
            )
            """
            unauth_df = pd.read_sql_query(query_unauth_esc, conn)
            for _, row in unauth_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'UNAUTHORIZED_PRIVILEGE_ESCALATION',
                    'description': "Service account performed privilege escalation without an approved change ticket."
                })
        except Exception:
            pass

        # 13. FIRST_TIME_SENSITIVE_ACCESS: First-time access to high-sensitivity resources
        try:
            high_res_list = "', '".join(HIGH_SENSITIVITY_RESOURCES)
            query_first_access = f"""
            SELECT ral.identity_id, ral.resource, ral.timestamp
            FROM resource_access_logs ral
            WHERE ral.resource IN ('{high_res_list}')
            GROUP BY ral.identity_id, ral.resource
            HAVING COUNT(*) = 1
            """
            first_access_df = pd.read_sql_query(query_first_access, conn)
            for _, row in first_access_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'FIRST_TIME_SENSITIVE_ACCESS',
                    'description': f"First-time access to high-sensitivity resource: {row['resource']}."
                })
        except Exception:
            pass

        # 14. OUTSIDE_NORMAL_ACTIVITY_WINDOW: Access outside baseline hours
        try:
            query_outside_hours = """
            SELECT ral.identity_id, ral.timestamp,
                   CAST(strftime('%H', ral.timestamp) AS INTEGER) AS access_hour,
                   bl.start_hour, bl.end_hour
            FROM resource_access_logs ral
            JOIN identity_baselines bl ON ral.identity_id = bl.identity_id
            WHERE CAST(strftime('%H', ral.timestamp) AS INTEGER) < bl.start_hour
               OR CAST(strftime('%H', ral.timestamp) AS INTEGER) > bl.end_hour
            GROUP BY ral.identity_id
            """
            outside_df = pd.read_sql_query(query_outside_hours, conn)
            for _, row in outside_df.iterrows():
                anomalies.append({
                    'identity_id': row['identity_id'],
                    'anomaly_type': 'OUTSIDE_NORMAL_ACTIVITY_WINDOW',
                    'description': f"Access at hour {row['access_hour']} outside baseline window ({row['start_hour']}:00-{row['end_hour']}:00)."
                })
        except Exception:
            pass

        # 15. SERVICE_ACCOUNT_COMPROMISE: Composite — SA type + unauthorized escalation + first-time sensitive + outside hours
        try:
            flagged_ids = set(a['identity_id'] for a in anomalies
                              if a['anomaly_type'] in (
                                  'UNAUTHORIZED_PRIVILEGE_ESCALATION',
                                  'FIRST_TIME_SENSITIVE_ACCESS',
                                  'OUTSIDE_NORMAL_ACTIVITY_WINDOW'
                              ))
            if flagged_ids:
                placeholders = ','.join(['?' for _ in flagged_ids])
                sa_flagged = pd.read_sql_query(
                    f"SELECT DISTINCT identity_id FROM identities "
                    f"WHERE identity_id IN ({placeholders}) "
                    f"AND type IN ('ServiceAccount', 'PrivilegedServiceAccount')",
                    conn, params=list(flagged_ids)
                )
                for _, row in sa_flagged.iterrows():
                    anomalies.append({
                        'identity_id': row['identity_id'],
                        'anomaly_type': 'SERVICE_ACCOUNT_COMPROMISE',
                        'description': "Composite indicator: Service account showing multiple compromise signals (unauthorized escalation, sensitive access, off-hours activity)."
                    })
        except Exception:
            pass

        conn.close()
        return pd.DataFrame(anomalies)

if __name__ == "__main__":
    engine = AnomalyDetectionEngine()
    df = engine.detect_anomalies()
    print(df.head(10))
    print(f"Total anomalies detected: {len(df)}")
    print(f"\nAnomaly type breakdown:")
    print(df['anomaly_type'].value_counts().to_string())
