package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"encoding/base64"
	"encoding/pem"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"lambda-ca-kms/kms"
)

type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func HandleGetJWKS(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao carregar configuração"}, nil
	}

	client := awskms.NewFromConfig(cfg)

	var keys []JWK

	for _, pair := range []struct {
		kid string
		use string
		alg string
	}{
		{kms.JWTKeyID, "sig", "ES256"},
		{kms.JOSEKeyID, "enc", "ES256"},
	} {
		out, err := client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{
			KeyId: &pair.kid,
		})
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao obter chave pública"}, nil
		}

		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
		keys = append(keys, JWK{
			Kty: "EC",
			Kid: pair.kid,
			Use: pair.use,
			Alg: pair.alg,
			X5c: []string{base64.StdEncoding.EncodeToString(pemBlock)},
		})
	}

	jwks := JWKS{Keys: keys}
	body, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao serializar JWKS"}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(body),
	}, nil
}
