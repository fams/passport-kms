package handlers

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
	"net/http"
)

func HandleGetPublicKey(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	key, err := manager.JWKSPublicKey(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: err.Error()}, nil
	}
	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: string(key)}, nil
}
