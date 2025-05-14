output "kms_key_id" {
  value = aws_kms_key.jwt_signing_key.id
}

output "kms_key_arn" {
  value = aws_kms_key.jwt_signing_key.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.jwt_signing_alias.name
}

output "signing_role_arn" {
  value = local.sign_role_arn
}

