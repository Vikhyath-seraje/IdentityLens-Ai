locals {
  users_csv = csvdecode(file("${path.module}/users.csv"))
}

resource "aws_iam_user" "users" {
  for_each = { for row in local.users_csv : row.username => row }
  name     = each.key
  path     = "/"
}

# Create Access Keys for users (useful for Hackathon simulation)
resource "aws_iam_access_key" "keys" {
  for_each = aws_iam_user.users
  user     = each.value.name
}

resource "aws_iam_user_group_membership" "memberships" {
  for_each = { for row in local.users_csv : row.username => row }
  user     = aws_iam_user.users[each.key].name
  groups   = [
    aws_iam_group.groups[each.value.group].name
  ]
}
