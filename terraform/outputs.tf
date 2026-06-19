output "users" {
  value = {
    for u in aws_iam_user.users : u.name => {
      arn = u.arn
      id  = u.id
    }
  }
}

output "groups" {
  value = {
    for g in aws_iam_group.groups : g.name => {
      arn = g.arn
      id  = g.id
    }
  }
}

output "roles" {
  value = {
    for r in aws_iam_role.roles : r.name => {
      arn = r.arn
      id  = r.id
    }
  }
}

output "access_keys" {
  value     = {
    for k in aws_iam_access_key.keys : k.user => {
      id     = k.id
      secret = k.secret
    }
  }
  sensitive = true
}

output "resources" {
  value = {
    s3_customer_data    = aws_s3_bucket.customer_data.arn
    s3_financial        = aws_s3_bucket.financial_records.arn
    s3_backups          = aws_s3_bucket.internal_backups.arn
    ec2_prod_server_arn = aws_instance.prod_server.arn
  }
}
