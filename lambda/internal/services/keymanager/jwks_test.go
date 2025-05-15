package keymanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"go.uber.org/mock/gomock"
	"lambda-ca-kms/mocks"
)

type JWKSClaims struct {
	Iss  string      `json:"iss"`
	JWKS interface{} `json:"jwks"`
}

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

	realKeyDER, realPriv := generateFakeECDSAKey(t)

	mockKMS := mocks.NewMockKMSClient(ctrl)
	mockKMS.EXPECT().Sign(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			r, s, err := ecdsa.Sign(rand.Reader, realPriv, input.Message)
			if err != nil {
				return nil, err
			}
			sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if err != nil {
				return nil, err
			}
			return &kms.SignOutput{Signature: sig}, nil
		})

	pubKey := &realPriv.PublicKey

	tests := []struct {
		name    string
		keyData []byte
		spec    types.KeySpec
		expect  error
		useMock bool
	}{
		{"success", realKeyDER, types.KeySpecEccNistP256, nil, true},
		{"invalid key data", []byte("invalid"), types.KeySpecEccNistP256, ErrInvalidKey, false},
		{"unsupported key type", func() []byte {
			type unsupportedKey struct{}
			b, _ := x509.MarshalPKIXPublicKey(&unsupportedKey{})
			return b
		}(), types.KeySpecEccNistP256, ErrInvalidKey, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := KeyEntry{
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

			kw := NewKeyHolder(pub, cfg, entry)
			JWTKeys = []*KeyHolder{kw}
			JOSEKeys = []*KeyHolder{kw}
			JWKSKeys = []*KeyHolder{kw}

			jwks, err := GetJWKS(context.Background())
			assert.ErrorIs(t, err, tt.expect)

			if err == nil {
				parsed, err := jwt.Parse(jwks, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
						t.Fatalf("método de assinatura inesperado: %v", token.Method.Alg())
					}
					return pubKey, nil
				})
				if err != nil || !parsed.Valid {
					t.Fatalf("JWT inválido: %v", err)
				}

				payload, err := base64.RawURLEncoding.DecodeString(strings.Split(jwks, ".")[1])
				if err != nil {
					t.Fatalf("erro ao decodificar payload: %v", err)
				}
				var out JWKSClaims
				if err := json.Unmarshal(payload, &out); err != nil {
					t.Fatalf("payload inválido: %v", err)
				}
				if out.Iss != "jwks.ca.internal" {
					t.Errorf("issuer inesperado: %s", out.Iss)
				}
				if out.JWKS == nil {
					t.Error("jwks não encontrado no payload")
				}
			}
		})
	}
}
