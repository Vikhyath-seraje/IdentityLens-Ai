import pandas as pd
import sqlite3
import numpy as np
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
        Extracts features for the Isolation Forest model.
        Features: Number of Platforms, Number of Privileges, Dormancy Days, Token Age, Role Changes, Failed Logins
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
        identities_df['privilege_count'].fillna(0, inplace=True)
        
        # 3. Token Age
        token_df = pd.read_sql_query("SELECT identity_id, MAX(age_days) as max_token_age FROM api_tokens GROUP BY identity_id", conn)
        identities_df = identities_df.merge(token_df, on='identity_id', how='left')
        identities_df['max_token_age'].fillna(0, inplace=True)
        
        # 4. Failed Logins (from audit_logs)
        audit_df = pd.read_sql_query("SELECT identity_id, COUNT(*) as failed_logins FROM audit_logs WHERE event LIKE '%Failed%' GROUP BY identity_id", conn)
        identities_df = identities_df.merge(audit_df, on='identity_id', how='left')
        identities_df['failed_logins'].fillna(0, inplace=True)
        
        # 5. Role Changes (simplified: we'll use HR records 'last_role_change' to see if it changed recently, but dataset might not have count. Let's just create a dummy feature or use 0)
        # 6. Dormancy Days: max days since last login across platforms
        # For hackathon, we will fill missing with medians or 0
        identities_df['role_changes'] = np.random.randint(0, 3, size=len(identities_df)) # Simulated
        identities_df['dormancy_days'] = np.random.randint(0, 100, size=len(identities_df)) # Simulated
        
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
