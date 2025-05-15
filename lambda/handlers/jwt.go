package handlers

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"lambda-ca-kms/internal/services/keymanager"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
)

func HandleSignJWT(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	signed, err := keymanager.SignJWT(ctx, jwt.MapClaims{})
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao assinar jwt"}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: signed}, nil
}
