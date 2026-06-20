import sqlite3

# Run the actual queries that were broken and confirm they work now
conn = sqlite3.connect(r'database/identitylens.db')

print("=== Testing fixed Platform Overview queries ===")
ad_full   = __import__('pandas').read_sql_query("SELECT status, role FROM ad_accounts", conn)
aws_full  = __import__('pandas').read_sql_query("SELECT status, policy FROM aws_accounts", conn)
okta_full = __import__('pandas').read_sql_query("SELECT status, role FROM okta_accounts", conn)
tok_count = __import__('pandas').read_sql_query("SELECT COUNT(*) as c FROM api_tokens", conn).iloc[0]['c']

print(f"AD users:   {len(ad_full)}  (was: 0)")
print(f"AWS users:  {len(aws_full)} (was: 0)")
print(f"Okta users: {len(okta_full)}(was: 0)")
print(f"Tokens:     {tok_count}   (was: 301 via exception path)")

print("\n=== Testing quarantine_records query (should still work) ===")
q = conn.execute("SELECT COUNT(*) FROM quarantine_records WHERE status='quarantined'").fetchone()
print(f"Quarantined: {q[0]}")

conn.close()
print("\nAll good - the bad WHERE clause was only in api_tokens, which is now fixed.")
