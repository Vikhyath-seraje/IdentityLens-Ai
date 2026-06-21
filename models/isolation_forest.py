import pandas as pd
import sqlite3
import datetime
from sklearn.ensemble import IsolationForest
from backend.identity_resolver import IdentityResolver
from backend.privilege_analyzer import PrivilegeAnalyzer

class MLModel:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path
        self.resolver = IdentityResolver(db_path)
        self.priv_analyzer = PrivilegeAnalyzer(db_path)

    def extract_features(self):
        """
        Extracts deterministic features for the Isolation Forest model.
        Features: num_platforms, privilege_count, max_token_age, failed_logins,
                  role_changes, dormancy_days

        All features are computed from the database so the model produces
        stable, reproducible results (no random fills).
        """
        conn = sqlite3.connect(self.db_path)

        # 1. Number of Platforms
        identities_df = self.resolver.get_resolved_identities()
        def count_platforms(row):
            count = 0
            if pd.notna(row['ad_user']): count += 1
            if pd.notna(row['aws_user']): count += 1
            if pd.notna(row['okta_login']): count += 1
            return count

        identities_df['num_platforms'] = identities_df.apply(count_platforms, axis=1)

        # 2. Number of Privileges
        priv_df = self.priv_analyzer.analyze_all_identities()
        identities_df = identities_df.merge(priv_df[['identity_id', 'privilege_count']], on='identity_id', how='left')
        identities_df['privilege_count'] = identities_df['privilege_count'].fillna(0).astype(int)

        # 3. Token Age
        token_df = pd.read_sql_query("SELECT identity_id, MAX(age_days) as max_token_age FROM api_tokens GROUP BY identity_id", conn)
        identities_df = identities_df.merge(token_df, on='identity_id', how='left')
        identities_df['max_token_age'] = identities_df['max_token_age'].fillna(0).astype(int)

        # 4. Failed Logins (from audit_logs)
        audit_df = pd.read_sql_query("SELECT identity_id, COUNT(*) as failed_logins FROM audit_logs WHERE event LIKE '%Failed%' GROUP BY identity_id", conn)
        identities_df = identities_df.merge(audit_df, on='identity_id', how='left')
        identities_df['failed_logins'] = identities_df['failed_logins'].fillna(0).astype(int)

        # 5. Role Changes — count privilege-escalation / role-change events per identity
        role_df = pd.read_sql_query(
            "SELECT identity_id, COUNT(*) as role_changes "
            "FROM change_requests WHERE change_type IN ('PrivilegeEscalation','RoleChange') "
            "GROUP BY identity_id", conn)
        identities_df = identities_df.merge(role_df, on='identity_id', how='left')
        identities_df['role_changes'] = identities_df['role_changes'].fillna(0).astype(int)

        # 6. Dormancy Days — days since the most recent login across AD/AWS/Okta
        today = pd.Timestamp.now().normalize()
        login_cols = {}
        for tbl in ('ad_accounts', 'aws_accounts', 'okta_accounts'):
            login_cols[tbl] = pd.read_sql_query(
                "SELECT identity_id, last_login FROM " + tbl + " WHERE last_login IS NOT NULL", conn)
        # pick the most recent last_login per identity across the three platforms
        recent = identities_df[['identity_id']].copy()
        recent['latest_login'] = None
        for tbl, ldf in login_cols.items():
            ldf = ldf.rename(columns={'last_login': '_ll'})
            recent = recent.merge(ldf, on='identity_id', how='left')
            recent['latest_login'] = recent[['latest_login', '_ll']].apply(
                lambda r: r['_ll'] if (pd.isna(r['latest_login']) or
                                       (pd.notna(r['_ll']) and str(r['_ll']) > str(r['latest_login'])))
                else r['latest_login'], axis=1)
            recent = recent.drop(columns=['_ll'])
        def _dormancy(ll):
            if pd.isna(ll) or ll == '':
                return 365
            try:
                ts = pd.to_datetime(ll, errors='coerce')
                if pd.isna(ts):
                    return 365
                delta = (today - ts.normalize()).days
                return max(delta, 0)
            except Exception:
                return 365
        recent['dormancy_days'] = recent['latest_login'].apply(_dormancy)
        identities_df = identities_df.merge(
            recent[['identity_id', 'dormancy_days']], on='identity_id', how='left')
        identities_df['dormancy_days'] = identities_df['dormancy_days'].fillna(365).astype(int)

        conn.close()

        return identities_df

    def train_and_predict(self):
        """
        Trains Isolation Forest and predicts anomalies (-1 for anomaly, 1 for normal).
        """
        df = self.extract_features()
        features = ['num_platforms', 'privilege_count', 'max_token_age', 'failed_logins', 'role_changes', 'dormancy_days']

        X = df[features]

        # Isolation Forest
        clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        df['anomaly_score'] = clf.fit_predict(X)
        df['anomaly_decision_function'] = clf.decision_function(X)

        return df

if __name__ == "__main__":
    model = MLModel()
    results = model.train_and_predict()
    print("Anomalies Detected by ML:")
    print(results[results['anomaly_score'] == -1].head())
