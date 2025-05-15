package keymanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrCSRInvalid     = errors.New("CSR inválido")
	ErrNotImplemented = errors.New("Not implemented")
)

func SignCSR(ctx context.Context, csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", ErrCSRInvalid
	}

	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}

	return "", ErrNotImplemented
}
