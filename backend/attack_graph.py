import sqlite3
import pandas as pd
import networkx as nx

# Import high-sensitivity resources (with fallback for standalone execution)
try:
    from backend.anomaly_detection import HIGH_SENSITIVITY_RESOURCES
except ImportError:
    HIGH_SENSITIVITY_RESOURCES = {
        'hr_database.salaries', 'financial-records', 'customer-data',
        'production-secrets', 'source-code'
    }

class AttackGraphGenerator:
    def __init__(self, db_path='database/identitylens.db'):
        self.db_path = db_path

    def generate_graph(self):
        """
        Generates a NetworkX graph representing the attack paths.
        Nodes: Identities, Groups, Roles, Platforms, Resources.
        Edges: Relationships (e.g., Identity -> Group -> Role -> Platform).
        """
        conn = sqlite3.connect(self.db_path)
        G = nx.DiGraph()

        # Add Identities with identity_type attribute
        identities = pd.read_sql_query("SELECT identity_id, type FROM identities", conn)
        for _, row in identities.iterrows():
            G.add_node(row['identity_id'], type='Identity', label=row['identity_id'],
                       identity_type=row['type'])

        # Add Groups from memberships
        groups = pd.read_sql_query('SELECT "group", parent_group FROM group_memberships', conn)
        for _, row in groups.iterrows():
            G.add_node(row['group'], type='Group', label=row['group'])
            if pd.notna(row['parent_group']):
                G.add_node(row['parent_group'], type='Group', label=row['parent_group'])
                G.add_edge(row['group'], row['parent_group'], relation='MEMBER_OF')

        # Get currently quarantined identities
        quarantined_ids = set()
        try:
            quarantined_df = pd.read_sql_query("""
                SELECT identity_id FROM (
                    SELECT identity_id, status, MAX(timestamp)
                    FROM quarantine_records
                    GROUP BY identity_id
                ) WHERE status = 'quarantined'
            """, conn)
            quarantined_ids = set(quarantined_df['identity_id'].tolist())
        except Exception as e:
            pass

        # Quarantine Role node
        QUARANTINE_ROLE = 'Quarantined'
        G.add_node(QUARANTINE_ROLE, type='Role', label=QUARANTINE_ROLE,
                   quarantined=True)
        for qid in quarantined_ids:
            if qid not in G:
                continue
            G.add_edge(qid, QUARANTINE_ROLE, relation='QUARANTINED')

        # Add AD Roles (skip quarantined identities)
        ad_roles = pd.read_sql_query("SELECT identity_id, role FROM ad_accounts WHERE role IS NOT NULL", conn)
        for _, row in ad_roles.iterrows():
            if row['identity_id'] in quarantined_ids:
                continue
            G.add_node(row['role'], type='Role', label=row['role'])
            G.add_node('Active Directory', type='Platform', label='Active Directory')
            G.add_edge(row['identity_id'], row['role'], relation='HAS_ROLE')
            G.add_edge(row['role'], 'Active Directory', relation='ACCESS_TO')

        # Add AWS Policies
        aws_roles = pd.read_sql_query("SELECT identity_id, policy FROM aws_accounts WHERE policy IS NOT NULL", conn)
        for _, row in aws_roles.iterrows():
            if row['identity_id'] in quarantined_ids:
                continue
            G.add_node(row['policy'], type='Role', label=row['policy'])
            G.add_node('AWS IAM', type='Platform', label='AWS IAM')
            G.add_edge(row['identity_id'], row['policy'], relation='HAS_POLICY')
            G.add_edge(row['policy'], 'AWS IAM', relation='ACCESS_TO')

        # Add Okta Roles
        okta_roles = pd.read_sql_query("SELECT identity_id, role FROM okta_accounts WHERE role IS NOT NULL", conn)
        for _, row in okta_roles.iterrows():
            if row['identity_id'] in quarantined_ids:
                continue
            G.add_node(row['role'], type='Role', label=row['role'])
            G.add_node('Okta', type='Platform', label='Okta')
            G.add_edge(row['identity_id'], row['role'], relation='HAS_ROLE')
            G.add_edge(row['role'], 'Okta', relation='ACCESS_TO')

        # ── Resource Access Edges (ITDR) ──────────────────────────────────────────
        # Add resource nodes and edges for high-sensitivity resource access
        try:
            high_res_list = list(HIGH_SENSITIVITY_RESOURCES)
            placeholders = ','.join(['?' for _ in high_res_list])
            resource_access = pd.read_sql_query(
                f"SELECT DISTINCT identity_id, resource FROM resource_access_logs "
                f"WHERE resource IN ({placeholders})",
                conn, params=high_res_list
            )
            for _, row in resource_access.iterrows():
                res_node = row['resource']
                G.add_node(res_node, type='Resource', label=res_node)
                if row['identity_id'] not in quarantined_ids:
                    G.add_edge(row['identity_id'], res_node, relation='ACCESSES')
        except Exception:
            pass

        conn.close()
        return G

if __name__ == "__main__":
    generator = AttackGraphGenerator()
    G = generator.generate_graph()
    print(f"Graph generated with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")
