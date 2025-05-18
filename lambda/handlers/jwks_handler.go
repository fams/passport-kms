package handlers

import (
	"context"
	"errors"
	"github.com/aws/aws-lambda-go/events"
	"lambda-ca-kms/internal/services/keymanager"
	"net/http"
)

func HandleGetJWKS(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	signed, err := manager.JWKSCurrent(ctx)
	if err != nil {
		var msg string
		switch {
		case errors.Is(err, keymanager.ErrInvalidKey):
			msg = "erro ao decodificar chave pública"
		case errors.Is(err, keymanager.ErrConfiguredKeyNotSupported):
			msg = "chave pública com tipo não suportado"
		case errors.Is(err, keymanager.ErrCouldNotSignKey):
			msg = "erro ao assinar JWKS"
		default:
			msg = "erro interno"
		}
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: msg}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/jwt"},
		Body:       signed,
	}, nil
}
