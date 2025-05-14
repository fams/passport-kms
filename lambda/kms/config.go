package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

var (
	JWTKeyID  string
	JOSEKeyID string
	JWKSKeyID string

	JWTSigner  *jwtkms.Config
	JOSESigner *jwtkms.Config
	JWKSSigner *jwtkms.Config
)

func InitKMS() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic("falha ao carregar configuração AWS")
	}

	client := kms.NewFromConfig(cfg)

	JWTSigner = jwtkms.NewKMSConfig(client, JWTKeyID, false)
	JOSESigner = jwtkms.NewKMSConfig(client, JOSEKeyID, false)
	JWKSSigner = jwtkms.NewKMSConfig(client, JWKSKeyID, false)
}
