package main

import (
	"context"
	"lambda-ca-kms/handlers"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

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
