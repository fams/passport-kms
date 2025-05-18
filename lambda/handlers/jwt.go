package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
)

func HandleSignJWT(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(req.Body), &claims); err != nil || claims == nil {
		claims = jwt.MapClaims{"iss": "default"}
	}

	signed, err := manager.SignJWT(ctx, claims)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao assinar jwt"}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: signed}, nil
}
