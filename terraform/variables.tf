# Root module (variables.tf)

variable "sso_admin_principal_arn" {
  description = "ARN da role ou user SSO com acesso de administração à chave KMS"
  type        = string
}

variable "trusted_service" {
  description = "Serviço que irá assumir a role para assinatura (ex: ec2.amazonaws.com, ecs-tasks.amazonaws.com)"
  type        = string
  default     = "ec2.amazonaws.com"
}
