package handlers

import (
	"context"
	"encoding/pem"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	kConfig "lambda-ca-kms/keymanager"
)

func HandleGetPublicKey(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	out := kConfig.GetJWKSSigner().PubKey
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: string(pemBlock)}, nil
}
