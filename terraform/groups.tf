locals {
  groups_csv = csvdecode(file("${path.module}/groups.csv"))
  
  # Map groups to their policies by splitting the delimited list
  group_policies_raw = flatten([
    for row in local.groups_csv : [
      for policy in split("|", row.managed_policies) : {
        group  = row.group_name
        policy = policy
      }
    ]
  ])

  group_policies = {
    for idx, gp in local.group_policies_raw : "${gp.group}_${idx}" => gp
  }
}

resource "aws_iam_group" "groups" {
  for_each = { for row in local.groups_csv : row.group_name => row }
  name     = each.key
  path     = "/"
}

resource "aws_iam_group_policy_attachment" "group_attachments" {
  for_each   = local.group_policies
  group      = aws_iam_group.groups[each.value.group].name
  policy_arn = each.value.policy
}
