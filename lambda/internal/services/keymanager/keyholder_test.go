package keymanager

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

func TestKeyHolderMethods(t *testing.T) {
	pub := &kms.GetPublicKeyOutput{
		KeyId:   strPtr("alias/test"),
		KeySpec: types.KeySpecEccNistP256,
	}
	cfg := &jwtkms.Config{}
	entry := KeyEntry{
		KeyID:     "alias/test",
		UseFrom:   time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	kw := NewKeyHolder(pub, cfg, entry)

	if kw.KeyId() != "alias/test" {
		t.Errorf("KeyId incorreto: %s", kw.KeyId())
	}
	if len(kw.Kid()) != 32 {
		t.Errorf("Kid com tamanho inesperado: %s", kw.Kid())
	}
	if kw.SigningMethod() == nil {
		t.Error("esperado método de assinatura não-nulo")
	}
}
