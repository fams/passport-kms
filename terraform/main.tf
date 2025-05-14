# Root module (main.tf)

module "kms_jwt_signer" {
  source = "./modules/kms_signer"
  sso_admin_principal_arn = var.sso_admin_principal_arn
  trusted_service         = var.trusted_service
  key_spec = "ECC_NIST_P256"
  key_alias = "jwt-signer"
}

module "kms_jwks_signer" {
  source = "./modules/kms_signer"
  sign_role_arn = module.kms_jwt_signer.signing_role_arn
  key_alias = "passport-signer"
  sso_admin_principal_arn = var.sso_admin_principal_arn
  trusted_service         = var.trusted_service
  key_spec = "RSA_4096"
}

module "kms_jwks_encrypter" {
  source = "./modules/kms_encrypter"
  key_alias = "passport-decrypter"
  sso_admin_principal_arn = var.sso_admin_principal_arn
  trusted_service         = var.trusted_service
  key_spec = "RSA_4096"
}