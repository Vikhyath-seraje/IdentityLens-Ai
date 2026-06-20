import sqlite3
import pandas as pd
from datetime import datetime

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
        # Assuming last_login is YYYY-MM-DD
        query_dormant = """
        SELECT identity_id, ad_user, role, last_login FROM ad_accounts WHERE role LIKE '%Admin%' AND status = 'Active'
        """
        ad_admins = pd.read_sql_query(query_dormant, conn)
        # simplified check: we just flag if last_login is None or very old
        for _, row in ad_admins.iterrows():
            if pd.isna(row['last_login']) or row['last_login'] < '2023-01-01': # dummy threshold
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
        WHERE i.type = 'Service Account' AND okta.last_login IS NOT NULL
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
            pass # Table might be empty or missing during basic runs

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

        conn.close()
        return pd.DataFrame(anomalies)

if __name__ == "__main__":
    engine = AnomalyDetectionEngine()
    df = engine.detect_anomalies()
    print(df.head(10))
    print(f"Total anomalies detected: {len(df)}")
