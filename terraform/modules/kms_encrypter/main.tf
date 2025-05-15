# Module: modules/kms_signer/main.tf

resource "aws_kms_key" "jose_enc_key" {
  description             = "Chave para encript de JOSE com KMS"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = var.key_spec
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "jose_enc_alias" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.jose_enc_key.id
}


resource "aws_iam_role" "jose_enc_role" {
  count = var.sign_role_arn == "" ? 1 : 0
  name = "jose_enc-role-${var.key_alias}"

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

