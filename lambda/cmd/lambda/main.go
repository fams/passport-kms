package main

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"lambda-ca-kms/handlers"
	"lambda-ca-kms/kms"
	"net/http"
	"os"
)

func init() {
	*kms.JWTKeyID = os.Getenv("KMS_KEY_JWT")
	*kms.JOSEKeyID = os.Getenv("KMS_KEY_JOSE")
	*kms.JWKSKeyID = os.Getenv("KMS_KEY_JWKS")
	kms.InitKMS()
}
func main() {
	lambda.Start(func(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		switch req.Path {
		case "/sign-csr":
			return handlers.HandleSignCSR(ctx, req)
		case "/sign-jwt":
			return handlers.HandleSignJWT(ctx, req)
		case "/public-key":
			return handlers.HandleGetPublicKey(ctx, req)
		default:
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusNotFound,
				Body:       "rota não encontrada",
			}, nil
		}
	})
}
