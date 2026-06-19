import os
import json
import subprocess
import sqlite3
import boto3

DB_PATH = 'database/identitylens.db'
TERRAFORM_DIR = 'terraform'

class TerraformManager:
    def __init__(self):
        self.tf_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), TERRAFORM_DIR)

    def _run_cmd(self, cmd):
        try:
            result = subprocess.run(
                cmd,
                cwd=self.tf_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise Exception(f"Terraform command failed: {e.stderr}")

    def init_environment(self):
        """Run terraform init."""
        return self._run_cmd(["terraform", "init"])

    def deploy_environment(self):
        """Run terraform apply."""
        self.init_environment()
        return self._run_cmd(["terraform", "apply", "-auto-approve"])

    def destroy_environment(self):
        """Run terraform destroy."""
        self.init_environment()
        return self._run_cmd(["terraform", "destroy", "-auto-approve"])

    def get_terraform_output(self):
        """Run terraform output -json and parse it."""
        try:
            out = self._run_cmd(["terraform", "output", "-json"])
            return json.loads(out)
        except Exception:
            return None

    def sync_aws_identities(self):
        """Sync terraform outputs to local SQLite database mapping users to identities."""
        outputs = self.get_terraform_output()
        if not outputs:
            return "No outputs available to sync. Did you deploy?"

        users = outputs.get('users', {}).get('value', {})
        access_keys = outputs.get('access_keys', {}).get('value', {})

        conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(__file__)), DB_PATH))
        
        # Sync users to aws_accounts table
        for user_name, data in users.items():
            arn = data.get('arn')
            # For hackathon, we assume username matches the AD identity partially or we assign a mock identity
            # Fetch identity_id based on username if it exists, else use username as identity
            identity_id = user_name.replace(".", "").upper()[:6]
            
            # Check if exists
            exists = conn.execute("SELECT 1 FROM aws_accounts WHERE account_id = ?", (user_name,)).fetchone()
            if exists:
                conn.execute(
                    "UPDATE aws_accounts SET arn = ?, status = 'Active' WHERE account_id = ?",
                    (arn, user_name)
                )
            else:
                # Need to map to a random identity from our identities table or insert new
                # For simplicity, we just inject it directly to aws_accounts
                conn.execute(
                    "INSERT INTO aws_accounts (identity_id, account_id, arn, policy, status) VALUES (?, ?, ?, ?, ?)",
                    (f"EMP{len(users)}", user_name, arn, "GroupAssigned", "Active")
                )

        conn.commit()
        conn.close()
        return f"Synced {len(users)} users to local database."

    def refresh_aws_environment(self):
        """Use boto3 to fetch actual AWS state and drift."""
        iam = boto3.client('iam')
        try:
            paginator = iam.get_paginator('list_users')
            aws_users = []
            for response in paginator.paginate():
                aws_users.extend(response['Users'])
            return f"Successfully fetched {len(aws_users)} users from AWS API."
        except Exception as e:
            return f"Boto3 API error: {str(e)}"
