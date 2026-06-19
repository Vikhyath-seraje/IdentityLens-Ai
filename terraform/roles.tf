locals {
  roles_csv = csvdecode(file("${path.module}/roles.csv"))
  
  role_policies_raw = flatten([
    for row in local.roles_csv : [
      for policy in split("|", row.managed_policies) : {
        role   = row.role_name
        policy = policy
      } if row.managed_policies != ""
    ]
  ])

  role_policies = {
    for idx, rp in local.role_policies_raw : "${rp.role}_${idx}" => rp
  }
}

# Trust policy allowing EC2 or lambda to assume the roles (just as a placeholder)
data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "roles" {
  for_each           = { for row in local.roles_csv : row.role_name => row }
  name               = each.key
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "role_attachments" {
  for_each   = local.role_policies
  role       = aws_iam_role.roles[each.value.role].name
  policy_arn = each.value.policy
}

# Custom Deny All Policy for the QuarantineRole
resource "aws_iam_policy" "quarantine_deny_all" {
  name        = "QuarantineDenyAll"
  description = "Explicitly deny all actions for quarantined identities"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Deny"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "quarantine_role_attachment" {
  role       = aws_iam_role.roles["QuarantineRole"].name
  policy_arn = aws_iam_policy.quarantine_deny_all.arn
}
