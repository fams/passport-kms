package keymanager

import (
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"strings"
	"testing"
)

func TestNewKeyWrapper(t *testing.T) {
	pub := &kms.GetPublicKeyOutput{
		KeyId:   strPtr("alias/test"),
		KeySpec: types.KeySpecEccNistP256,
	}
	cfg := &jwtkms.Config{}
	entry := KeyEntry{
		KeyID:     "alias/test",
		UseFrom:   mustParse(t, "2024-01-01T00:00:00Z"),
		ExpiresAt: mustParse(t, "2025-01-01T00:00:00Z"),
	}
	kw := NewKeyHolder(pub, cfg, entry)

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"keyID", kw.keyID, entry.KeyID},
		{"UseFrom", kw.UseFrom, entry.UseFrom},
		{"ExpiresAt", kw.ExpiresAt, entry.ExpiresAt},
		{"PubKeyPtr", kw.PubKey, pub},
		{"ConfigPtr", kw.config, cfg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("esperado %v, obtido %v", tt.want, tt.got)
			}
		})
	}
}

func TestKid_HashIsDeterministicAndSafe(t *testing.T) {
	pub := &kms.GetPublicKeyOutput{
		KeyId:   strPtr("arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678"),
		KeySpec: types.KeySpecRsa2048,
	}
	kw := &KeyHolder{PubKey: pub}
	kid := kw.Kid()

	t.Run("Determinismo", func(t *testing.T) {
		if kid != kw.Kid() {
			t.Errorf("KID não é determinístico")
		}
	})
	t.Run("Sem vazamento de ARN", func(t *testing.T) {
		if strings.ContainsAny(kid, "+/=") || strings.Contains(kid, "aws") {
			t.Errorf("KID vazou ARN ou contém símbolos inválidos: %s", kid)
		}
	})
	t.Run("Tamanho fixo", func(t *testing.T) {
		if len(kid) != 32 {
			t.Errorf("esperado tamanho 32, obtido %d", len(kid))
		}
	})
}

func TestSigningMethod(t *testing.T) {
	tests := []struct {
		name string
		spec types.KeySpec
		want *jwtkms.KMSSigningMethod
	}{
		{"RSA2048", types.KeySpecRsa2048, jwtkms.SigningMethodPS256},
		{"ECC P256", types.KeySpecEccNistP256, jwtkms.SigningMethodECDSA256},
		{"Unknown", types.KeySpec("Unknown"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kw := &KeyHolder{PubKey: &kms.GetPublicKeyOutput{KeySpec: tt.spec}}
			got := kw.SigningMethod()
			if got != tt.want {
				t.Errorf("esperado %v, obtido %v", tt.want, got)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
