package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestHandleSignCSR(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("falha ao gerar chave: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		t.Fatalf("falha ao criar CSR: %v", err)
	}

	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	req := events.APIGatewayProxyRequest{Body: string(pemCSR)}
	resp, err := HandleSignCSR(context.Background(), req)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	if resp.StatusCode != 501 {
		t.Errorf("esperado 501 Not Implemented, obtido %d", resp.StatusCode)
	}
}
