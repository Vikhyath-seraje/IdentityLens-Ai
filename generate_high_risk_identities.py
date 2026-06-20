import pandas as pd
import os
import random
from datetime import datetime, timedelta

DATA_DIR = 'data'

def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        return pd.read_csv(path)
    else:
        # Return an empty dataframe, but we might need schema if it's new.
        # We assume most tables exist. For identity_groups, we'll return empty DF with columns if not exist.
        if filename == 'identity_groups.csv':
            return pd.DataFrame(columns=['identity_id', 'group_name'])
        return pd.DataFrame()

def save_csv(df, filename):
    df.to_csv(os.path.join(DATA_DIR, filename), index=False)

def update_or_add_row(df, key_col, key_val, new_data):
    if key_col in df.columns and (df[key_col] == key_val).any():
        idx = df[df[key_col] == key_val].index[0]
        for k, v in new_data.items():
            df.at[idx, k] = v
    else:
        new_row = new_data.copy()
        new_row[key_col] = key_val
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    return df

def main():
    print("Loading CSVs...")
    identities_df = load_csv('identities.csv')
    ad_accounts_df = load_csv('ad_accounts.csv')
    aws_accounts_df = load_csv('aws_accounts.csv')
    okta_accounts_df = load_csv('okta_accounts.csv')
    api_tokens_df = load_csv('api_tokens.csv')
    audit_logs_df = load_csv('audit_logs.csv')
    hr_records_df = load_csv('hr_records.csv')
    offboarding_df = load_csv('offboarding_records.csv')
    group_memberships_df = load_csv('group_memberships.csv')
    identity_groups_df = load_csv('identity_groups.csv')

    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')

    identities = [
        {'id': 'CTR001', 'name': 'Chris Carter', 'type': 'Contractor', 'dept': 'Engineering'},
        {'id': 'EMP002', 'name': 'Emily Davis', 'type': 'Employee', 'dept': 'IT'},
        {'id': 'EMP003', 'name': 'Michael Dormer', 'type': 'Employee', 'dept': 'Operations'},
        {'id': 'SVC001', 'name': 'svc-db-sync', 'type': 'Service Account', 'dept': 'System'},
        {'id': 'EMP005', 'name': 'Sarah Token', 'type': 'Employee', 'dept': 'Engineering'},
        {'id': 'SVC002', 'name': 'svc-web-app', 'type': 'Service Account', 'dept': 'System'},
        {'id': 'EMP007', 'name': 'David Hacker', 'type': 'Employee', 'dept': 'IT'},
        {'id': 'CTR002', 'name': 'Oliver Orphan', 'type': 'Contractor', 'dept': 'Marketing'},
        {'id': 'EMP009', 'name': 'Isabella Traveler', 'type': 'Employee', 'dept': 'Sales'},
        {'id': 'EMP010', 'name': 'Charlie Shared', 'type': 'Employee', 'dept': 'Support'}
    ]

    for idt in identities:
        identities_df = update_or_add_row(identities_df, 'identity_id', idt['id'], {
            'name': idt['name'],
            'type': idt['type'],
            'department': idt['dept']
        })

    # 1. CTR001 - OFFBOARDING_GAP
    offboarding_df = update_or_add_row(offboarding_df, 'identity_id', 'CTR001', {
        'termination_date': '2024-01-15'
    })
    ad_accounts_df = update_or_add_row(ad_accounts_df, 'identity_id', 'CTR001', {'ad_user': 'ccarter', 'status': 'Active', 'role': 'Developer'})
    aws_accounts_df = update_or_add_row(aws_accounts_df, 'identity_id', 'CTR001', {'aws_user': 'ccarter', 'status': 'Active', 'policy': 'ReadOnly'})
    okta_accounts_df = update_or_add_row(okta_accounts_df, 'identity_id', 'CTR001', {'okta_user': 'ccarter', 'status': 'Suspended', 'role': 'User'})

    # 2. EMP002 - CROSS_PLATFORM_ADMIN
    ad_accounts_df = update_or_add_row(ad_accounts_df, 'identity_id', 'EMP002', {'ad_user': 'edavis', 'status': 'Active', 'role': 'Domain Admin'})
    aws_accounts_df = update_or_add_row(aws_accounts_df, 'identity_id', 'EMP002', {'aws_user': 'edavis', 'status': 'Active', 'policy': 'AdministratorAccess'})
    okta_accounts_df = update_or_add_row(okta_accounts_df, 'identity_id', 'EMP002', {'okta_user': 'edavis', 'status': 'Active', 'role': 'SuperAdmin'})

    # 3. EMP003 - DORMANT_ADMIN
    ad_accounts_df = update_or_add_row(ad_accounts_df, 'identity_id', 'EMP003', {'ad_user': 'mdormer', 'status': 'Active', 'role': 'Domain Admin', 'last_login': '2022-06-15'})
    aws_accounts_df = update_or_add_row(aws_accounts_df, 'identity_id', 'EMP003', {'aws_user': 'mdormer', 'status': 'Active', 'policy': 'ReadOnly', 'last_login': '2022-06-15'})

    # 4. SVC001 - NESTED_ESCALATION
    identity_groups_df = update_or_add_row(identity_groups_df, 'identity_id', 'SVC001', {'group_name': 'svc-db-sync'})
    # Ensure nested group structure exists
    groups_to_add = [
        {'group': 'svc-db-sync', 'parent_group': 'DatabaseAdmins'},
        {'group': 'DatabaseAdmins', 'parent_group': 'ITAdmins'},
        {'group': 'ITAdmins', 'parent_group': 'GlobalAdmins'}
    ]
    for g in groups_to_add:
        if not ((group_memberships_df['group'] == g['group']) & (group_memberships_df['parent_group'] == g['parent_group'])).any():
            group_memberships_df = pd.concat([group_memberships_df, pd.DataFrame([g])], ignore_index=True)

    # 5. EMP005 - TOKEN_ABUSE
    api_tokens_df = update_or_add_row(api_tokens_df, 'identity_id', 'EMP005', {'token_id': 'tok_emp005_abuse', 'age_days': 400})

    # 6. SVC002 - SERVICE_ACCOUNT_ABUSE
    okta_accounts_df = update_or_add_row(okta_accounts_df, 'identity_id', 'SVC002', {'okta_user': 'svc-web-app', 'status': 'Active', 'role': 'App', 'last_login': '2024-03-01'})

    # 7. EMP007 - PRIVILEGE_ESCALATION
    audit_logs_df = pd.concat([audit_logs_df, pd.DataFrame([{
        'timestamp': now_str, 'identity_id': 'EMP007', 'action': 'RoleAssigned', 'platform': 'AWS', 'detail': 'Self-assigned AdministratorAccess role', 'run_id': 'run_pe_1'
    }])], ignore_index=True)

    # 8. CTR002 - ORPHAN_CONTRACTOR
    hr_records_df = update_or_add_row(hr_records_df, 'identity_id', 'CTR002', {'manager_id': '', 'department': 'Marketing', 'title': 'Content Creator'})

    # 9. EMP009 - IMPOSSIBLE_TRAVEL
    audit_logs_df = pd.concat([audit_logs_df, pd.DataFrame([{
        'timestamp': now_str, 'identity_id': 'EMP009', 'action': 'Login', 'platform': 'Okta', 'detail': 'Impossible Travel: Login from US and CN within 5 mins', 'run_id': 'run_it_1'
    }])], ignore_index=True)

    # 10. EMP010 - CREDENTIAL_SHARING
    audit_logs_df = pd.concat([audit_logs_df, pd.DataFrame([{
        'timestamp': now_str, 'identity_id': 'EMP010', 'action': 'Login', 'platform': 'Okta', 'detail': 'Credential Sharing: 5+ IPs concurrently', 'run_id': 'run_cs_1'
    }])], ignore_index=True)

    print("Saving CSVs...")
    save_csv(identities_df, 'identities.csv')
    save_csv(ad_accounts_df, 'ad_accounts.csv')
    save_csv(aws_accounts_df, 'aws_accounts.csv')
    save_csv(okta_accounts_df, 'okta_accounts.csv')
    save_csv(api_tokens_df, 'api_tokens.csv')
    save_csv(audit_logs_df, 'audit_logs.csv')
    save_csv(hr_records_df, 'hr_records.csv')
    save_csv(offboarding_df, 'offboarding_records.csv')
    save_csv(group_memberships_df, 'group_memberships.csv')
    save_csv(identity_groups_df, 'identity_groups.csv')
    print("Done!")

if __name__ == '__main__':
    main()
