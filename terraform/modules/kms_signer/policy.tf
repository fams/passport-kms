data "aws_iam_policy_document" "kms_jwt_policy" {
  # depends_on = [aws_iam_role.jwt_signing_role]
  statement {
    sid = "AllowJWTSigningRole"
    actions = [
      "kms:Sign",
      "kms:GetPublicKey"
    ]
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [local.sign_role_arn]
    }
    resources = ["*"]
  }

  statement {
    sid = "AllowSSOAdminsFullAccess"
    actions = ["kms:*"]
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.sso_admin_principal_arn]
    }
    resources = ["*"]
  }

  statement {
    sid = "root"
    actions = ["kms:*"]
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers =  ["arn:aws:iam::696300981483:root"]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key_policy" "jwt_key_policy" {
  key_id = aws_kms_key.jwt_signing_key.key_id
  policy = data.aws_iam_policy_document.kms_jwt_policy.json
}
