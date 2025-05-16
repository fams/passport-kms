package keymanager

import (
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"strings"
	"testing"
)

func TestBuildIssuerConfig(t *testing.T) {
	jose := &KeyHolder{PubKey: &kms.GetPublicKeyOutput{KeyId: strPtr("jose-key")}}
	sign := []*KeyHolder{
		{PubKey: &kms.GetPublicKeyOutput{KeyId: strPtr("sig-1")}},
		{PubKey: &kms.GetPublicKeyOutput{KeyId: strPtr("sig-2")}},
	}
	out, err := buildIssuerConfig(sign, jose)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !strings.Contains(string(out), "jose-key") {
		t.Error("KID esperado não encontrado na saída")
	}
}
