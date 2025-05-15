package handlers

import (
	"context"
	"encoding/pem"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kConfig "lambda-ca-kms/kms"
)

func HandleGetPublicKey(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao carregar config"}, nil
	}

	client := awskms.NewFromConfig(awsCfg)
	out, err := client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{
		KeyId: &kConfig.JWKSKeyID,
	})
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao obter chave pública"}, nil
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: string(pemBlock)}, nil
}
