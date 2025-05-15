package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
	"lambda-ca-kms/kms"
)

func HandleSignJWT(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
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
	token := jwt.NewWithClaims(kms.JWTSigner.SignMethod, claims)
	signed, err := token.SignedString(kms.JWTSigner.WithContext(ctx))
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao assinar jwt"}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: signed}, nil
}
