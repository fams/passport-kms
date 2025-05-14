output "kms_key_id" {
  value = aws_kms_key.jose_enc_key.id
}

output "kms_key_arn" {
  value = aws_kms_key.jose_enc_key.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.jose_enc_alias.name
}

output "signing_role_arn" {
  value = var.sign_role_arn != ""? var.sign_role_arn : (length(aws_iam_role.jose_enc_role)>0?aws_iam_role.jose_enc_role[0].arn:null)
}

