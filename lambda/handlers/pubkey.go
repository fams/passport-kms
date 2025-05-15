package handlers

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
	"lambda-ca-kms/internal/services/keymanager"
	"net/http"
)

func HandleGetPublicKey(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	pemBlock, err := keymanager.GetPublicKey()
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: err.Error()}, nil
	}
	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: string(pemBlock)}, nil
}
