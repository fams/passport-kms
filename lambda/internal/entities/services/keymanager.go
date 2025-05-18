package services

import (
	"context"
)

type KeyManager interface {
	JWKSCurrent(ctx context.Context) (string, error)
	JWKSPublicKey(ctx context.Context) ([]byte, error)
	IssuerConfig(ctx context.Context) ([]byte, error)
	SignJWT(ctx context.Context, claims map[string]interface{}) (string, error)
}
