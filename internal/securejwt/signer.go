package securejwt

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

type Signer struct {
	kmsSigner *jwtkms.Config
}

func NewSigner(kmsKeyID string) (*Signer, error) {
	// Carrega a configuração padrão da AWS
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile("AdministratorAccess-696300981483"))
	if err != nil {
		return nil, err
	}

	// Cria o cliente KMS
	kmsClient := kms.NewFromConfig(cfg)

	// Cria a configuração do KMS para assinatura
	kmsConfig := jwtkms.NewKMSConfig(kmsClient, kmsKeyID, false)

	return &Signer{
		kmsSigner: kmsConfig,
	}, nil
}

func (s *Signer) SignJWT(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwtkms.SigningMethodECDSA256, jwt.MapClaims(claims))
	return token.SignedString(s.kmsSigner)
}
