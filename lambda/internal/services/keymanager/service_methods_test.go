package keymanager

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

func TestKeyManagerMethods(t *testing.T) {
	ctx := context.Background()

	pub := &kms.GetPublicKeyOutput{
		KeyId:     strPtr("test-key"),
		KeySpec:   types.KeySpecEccNistP256,
		PublicKey: []byte{48, 129, 135, 48}, // DER simulado
	}

	holder := &KeyHolder{
		PubKey:    pub,
		config:    &jwtkms.Config{}, // ✅ necessário
		UseFrom:   time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		keyID:     "test-key",
	}

	km := &keyManager{
		jwtKeys:           []*KeyHolder{holder},
		joseKeys:          []*KeyHolder{holder},
		jwksKeys:          []*KeyHolder{holder},
		issuer:            "https://issuer.example",
		expireInHours:     1,
		skewTimeInSeconds: 0,
		clock:             MockClock(time.Now()),
	}

	t.Run("JWKSCurrent", func(t *testing.T) {
		jwt, err := km.JWKSCurrent(ctx)
		if err != nil || jwt == "" {
			t.Errorf("erro ao gerar JWKS: %v", err)
		}
	})

	t.Run("JWKSPublicKey", func(t *testing.T) {
		pem, err := km.JWKSPublicKey(ctx)
		if err != nil || len(pem) == 0 {
			t.Errorf("erro ao exportar chave pública: %v", err)
		}
	})

	t.Run("IssuerConfig", func(t *testing.T) {
		json, err := km.IssuerConfig(ctx)
		if err != nil || len(json) == 0 {
			t.Errorf("erro ao gerar issuer config: %v", err)
		}
	})
}
func strPtr(s string) *string { return &s }
