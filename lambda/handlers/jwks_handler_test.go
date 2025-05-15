package handlers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"

	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"go.uber.org/mock/gomock"
	"lambda-ca-kms/handlers"
	"lambda-ca-kms/keymanager"
	"lambda-ca-kms/mocks"
)

func generateFakeECDSAKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("erro ao gerar chave ECDSA: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("erro ao serializar chave pública: %v", err)
	}
	return der, priv
}

func TestHandleGetJWKS_Table(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKMS := mocks.NewMockKMSClient(ctrl)
	mockKMS.EXPECT().Sign(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			r := struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(1)}
			sig, _ := asn1.Marshal(r)
			return &kms.SignOutput{Signature: sig}, nil
		})

	pubDER, _ := generateFakeECDSAKey(t)

	tests := []struct {
		name    string
		keyData []byte
		spec    types.KeySpec
		expect  int
		useMock bool
	}{
		{"success", pubDER, types.KeySpecEccNistP256, 200, true},
		{"invalid key data", []byte("invalid"), types.KeySpecEccNistP256, 500, false},
		{"unsupported key type", func() []byte {
			type unsupportedKey struct{}
			b, _ := x509.MarshalPKIXPublicKey(&unsupportedKey{})
			return b
		}(), types.KeySpecEccNistP256, 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := keymanager.KeyEntry{
				KeyID:     tt.name,
				UseFrom:   time.Now().Add(-1 * time.Hour),
				ExpiresAt: time.Now().Add(6 * time.Hour),
			}

			pub := &kms.GetPublicKeyOutput{
				KeyId:     strPtr(entry.KeyID),
				KeySpec:   tt.spec,
				PublicKey: tt.keyData,
			}

			var cfg *jwtkms.Config
			if tt.useMock {
				cfg = jwtkms.NewKMSConfig(mockKMS, entry.KeyID, false)
			} else {
				cfg = jwtkms.NewKMSConfig(nil, entry.KeyID, false)
			}

			kw := keymanager.NewKeyWrapper(pub, cfg, entry)
			keymanager.JWTKeys = []*keymanager.KeyWrapper{kw}
			keymanager.JOSEKeys = []*keymanager.KeyWrapper{kw}

			resp, _ := handlers.HandleGetJWKS(context.Background(), events.APIGatewayProxyRequest{})
			if resp.StatusCode != tt.expect {
				t.Errorf("esperado status %d, obtido %d", tt.expect, resp.StatusCode)
			}
			if tt.expect == 200 {
				if resp.Headers["Content-Type"] != "application/jwt" {
					t.Errorf("esperado Content-Type application/jwt, obtido %s", resp.Headers["Content-Type"])
				}
				if resp.Body == "" {
					t.Error("esperado corpo com JWT assinado, obtido vazio")
				}
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
