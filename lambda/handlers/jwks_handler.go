package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/aws/aws-lambda-go/events"
	"lambda-ca-kms/internal/services/keymanager"
	"math/big"
	"net/http"
)

type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func base64urlUInt(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func base64urlInt(i int) string {
	buf := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(buf)
}

func HandleGetJWKS(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	signedJWTKS, err := keymanager.GetJWKS(ctx)
	if err != nil {
		switch {
		case errors.Is(err, keymanager.ErrInvalidKey):
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao decodificar chave pública"}, nil
		case errors.Is(err, keymanager.ErrConfiguredKeyNotSupported):
			return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "chave pública com tipo não suportado"}, nil
		case errors.Is(err, keymanager.ErrCouldNotSignKey):
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao assinar JWKS"}, nil
		default:
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro interno"}, nil
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/jwt"},
		Body:       signedJWTKS,
	}, nil
}
