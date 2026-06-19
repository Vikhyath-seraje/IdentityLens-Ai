import sqlite3
import pandas as pd
import networkx as nx

class PrivilegeAnalyzer:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path

    def _build_group_graph(self):
        """
        Builds a directed graph of group memberships using NetworkX.
        """
        conn = sqlite3.connect(self.db_path)
        query = "SELECT [group], parent_group FROM group_memberships"
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        G = nx.DiGraph()
        for _, row in df.iterrows():
            if pd.notna(row['parent_group']):
                G.add_edge(row['group'], row['parent_group'])
        return G

    def get_effective_privileges(self, identity_id):
        """
        Calculates effective privileges for an identity across all platforms.
        This includes direct roles/policies and any inherited through group nesting.
        """
        conn = sqlite3.connect(self.db_path)
        
        # Get direct roles
        query = f"""
        SELECT 
            ad.role AS ad_role,
            aws.policy AS aws_policy,
            okta.role AS okta_role
        FROM identities i
        LEFT JOIN ad_accounts ad ON i.identity_id = ad.identity_id
        LEFT JOIN aws_accounts aws ON i.identity_id = aws.identity_id
        LEFT JOIN okta_accounts okta ON i.identity_id = okta.identity_id
        WHERE i.identity_id = '{identity_id}'
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            return []
            
        direct_privileges = []
        row = df.iloc[0]
        if pd.notna(row['ad_role']): direct_privileges.append(row['ad_role'])
        if pd.notna(row['aws_policy']): direct_privileges.append(row['aws_policy'])
        if pd.notna(row['okta_role']): direct_privileges.append(row['okta_role'])
        
        G = self._build_group_graph()
        effective_privileges = set(direct_privileges)
        
        # Resolve nested privileges
        for priv in direct_privileges:
            if priv in G:
                # Add all ancestors (parent groups) in the graph
                ancestors = nx.ancestors(G, priv)
                effective_privileges.update(ancestors)
                
        return list(effective_privileges)

    def analyze_all_identities(self):
        """
        Returns a DataFrame with effective privileges for all identities.
        """
        conn = sqlite3.connect(self.db_path)
        query = "SELECT identity_id FROM identities"
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        df['effective_privileges'] = df['identity_id'].apply(self.get_effective_privileges)
        df['privilege_count'] = df['effective_privileges'].apply(len)
        return df

if __name__ == "__main__":
    analyzer = PrivilegeAnalyzer()
    df = analyzer.analyze_all_identities()
    print(df.head())
