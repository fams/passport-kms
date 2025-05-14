package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"time"
)

const KMS_KEY_ID = "alias/ca-key"

var signer *KMSSigner

func init() {
	ctx := context.Background()
	var err error
	signer, err = NewKMSSigner(ctx, KMS_KEY_ID)
	if err != nil {
		panic(err)
	}
}

func handler(req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	switch req.RawPath {
	case "/sign-csr":
		cert, err := SignCSR(signer, []byte(req.Body))
		if err != nil {
			return response(500, err.Error()), nil
		}
		return response(200, cert), nil

	case "/sign-jwt":
		var payload map[string]interface{}
		err := json.Unmarshal([]byte(req.Body), &payload)
		if err != nil {
			return response(400, "invalid JSON")
		}
		payload["exp"] = time.Now().Add(time.Hour).Unix()

		token, err := SignJWT(signer, payload)
		if err != nil {
			return response(500, err.Error()), nil
		}
		return response(200, token), nil

	case "/ca-public-key":
		pub, err := signer.GetPublicKeyPEM(context.Background())
		if err != nil {
			return response(500, err.Error()), nil
		}
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/plain"},
			Body:       pub,
		}, nil

	default:
		return response(404, "Not Found"), nil
	}
}

func response(status int, body string) events.APIGatewayV2HTTPResponse {
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Body:       body,
	}
}

func main() {
	lambda.Start(handler)
}
