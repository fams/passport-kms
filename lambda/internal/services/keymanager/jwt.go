package keymanager

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func SignJWT(ctx context.Context, customKeys jwt.Claims) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Audience:  []string{"api.exemplo.com"},
		ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		ID:        "1234-5678",
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    "sso.exemplo.com",
		NotBefore: jwt.NewNumericDate(now),
		Subject:   "usuario@exemplo.com",
	}
	token := jwt.NewWithClaims(GetJWTSigner().SigningMethod(), claims)
	signed, err := token.SignedString(GetJWTSigner().WithContext(ctx))
	if err != nil {
		return "", err
	}

	return signed, nil
}
