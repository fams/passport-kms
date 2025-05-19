package keymanager

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"testing"
)

func TestBuildIssuerConfig(t *testing.T) {
	sign := []*KeyHolder{
		{PubKey: &kms.GetPublicKeyOutput{KeyId: strPtr("sig-1")}, keyID: "sig-1"},
	}
	jose := &KeyHolder{PubKey: &kms.GetPublicKeyOutput{KeyId: strPtr("jose-1")}, keyID: "jose-1"}
	out, err := buildIssuerConfig(sign, jose)
	if err != nil {
		t.Fatalf("erro ao construir config: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	if _, ok := result["issuer"]; !ok {
		t.Error("issuer ausente no JSON")
	}
	if _, ok := result["signing_keys"]; !ok {
		t.Error("signing_keys ausente no JSON")
	}
	if _, ok := result["decryption_keys"]; !ok {
		t.Error("decryption_keys ausente no JSON")
	}
}
