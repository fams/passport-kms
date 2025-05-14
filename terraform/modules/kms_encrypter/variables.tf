# Module: modules/kms_signer/variables.tf

variable "sso_admin_principal_arn" {
  description = "ARN do administrador SSO da chave KMS"
  type        = string
}

variable "trusted_service" {
  description = "Serviço que pode assumir a role de encryption"
  type        = string
}

variable "key_spec" {
  description = "KMS Key Specification"
  type = string
}
variable "key_alias" {
  description = "KMS Key Alias"
  type = string
}
variable "sign_role_arn"{
  description = "IAM sign an role ARN"
  type = string
  default = ""
}