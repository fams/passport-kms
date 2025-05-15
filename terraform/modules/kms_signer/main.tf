# Module: modules/kms_signer/main.tf
locals {
  sign_role_arn = var.sign_role_arn != "" ? var.sign_role_arn : (length(aws_iam_role.jwt_signing_role)>0?aws_iam_role.jwt_signing_role[0].arn:null)
}
resource "aws_kms_key" "jwt_signing_key" {
  description             = "Chave para assinatura de JWTs com KMS"
  key_usage               = "SIGN_VERIFY"
  customer_master_key_spec = var.key_spec
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "jwt_signing_alias" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.jwt_signing_key.id
}


resource "aws_iam_role" "jwt_signing_role" {
  count = var.sign_role_arn == "" ? 1 : 0
  name = "jwt-signing-role-${var.key_alias}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = var.trusted_service
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}


# resource "aws_iam_role_policy" "jwt_signing_policy" {
#   count = var.sign_role_arn == "" ? 1 : 0
#   name ="kms-signing-policy-${var.key_alias}"
#   role = aws_iam_role.jwt_signing_role[0].id
#
#   policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Action = [
#           "kms:Sign",
#           "kms:GetPublicKey"
#         ],
#         Resource = "*"
#       }
#     ]
#   })
# }