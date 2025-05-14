package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
)

func HandleSignCSR(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	block, _ := pem.Decode([]byte(req.Body))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "CSR inválido"}, nil
	}

	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "Erro ao analisar CSR"}, nil
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusNotImplemented, Body: "assinatura de CSR não implementada"}, nil
}
