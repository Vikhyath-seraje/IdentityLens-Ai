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

        # 2. Old API Token: Tokens older than 90 days
        query_tokens = "SELECT identity_id, age_days FROM api_tokens WHERE age_days > 90"
        old_tokens = pd.read_sql_query(query_tokens, conn)
        for _, row in old_tokens.iterrows():
            anomalies.append({
                'identity_id': row['identity_id'],
                'anomaly_type': 'Old API Token',
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

        conn.close()
        return pd.DataFrame(anomalies)

if __name__ == "__main__":
    engine = AnomalyDetectionEngine()
    df = engine.detect_anomalies()
    print(df.head(10))
    print(f"Total anomalies detected: {len(df)}")
