import sqlite3
import pandas as pd

class IdentityResolver:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path

    def get_resolved_identities(self):
        """
        Correlates identities across AD, AWS, and Okta.
        Returns a DataFrame with the joined data.
        """
        conn = sqlite3.connect(self.db_path)
        query = """
        SELECT 
            i.identity_id,
            i.name,
            i.type,
            i.department,
            ad.ad_user,
            ad.status AS ad_status,
            ad.role AS ad_role,
            aws.aws_user,
            aws.status AS aws_status,
            aws.policy AS aws_policy,
            okta.okta_login,
            okta.status AS okta_status,
            okta.role AS okta_role
        FROM identities i
        LEFT JOIN ad_accounts ad ON i.identity_id = ad.identity_id
        LEFT JOIN aws_accounts aws ON i.identity_id = aws.identity_id
        LEFT JOIN okta_accounts okta ON i.identity_id = okta.identity_id
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df

    def get_identity_summary(self):
        """
        Returns summary statistics about the identities.
        """
        df = self.get_resolved_identities()
        total_identities = len(df)
        type_counts = df['type'].value_counts().to_dict()
        dept_counts = df['department'].value_counts().to_dict()
        
        # Calculate how many have accounts in all 3 platforms
        has_all_three = len(df.dropna(subset=['ad_user', 'aws_user', 'okta_login']))
        
        return {
            'total_identities': total_identities,
            'types': type_counts,
            'departments': dept_counts,
            'has_all_three_platforms': has_all_three
        }

if __name__ == "__main__":
    resolver = IdentityResolver()
    df = resolver.get_resolved_identities()
    print(df.head())
    print(resolver.get_identity_summary())
