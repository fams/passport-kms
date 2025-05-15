package keymanager

import (
	"context"
	"lambda-ca-kms/mocks"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"go.uber.org/mock/gomock"
)

func strPtr(s string) *string { return &s }

func mustParse(t *testing.T, s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("erro ao parsear tempo: %v", err)
	}
	return tm
}

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

func TestApplyExpirationPolicy(t *testing.T) {
	t.Run("Política aplicada corretamente", func(t *testing.T) {
		entries := []KeyEntry{
			{KeyID: "k1", UseFrom: mustParse(t, "2024-01-01T00:00:00Z")},
			{KeyID: "k2", UseFrom: mustParse(t, "2025-01-01T00:00:00Z")},
			{KeyID: "k3", UseFrom: mustParse(t, "2026-01-01T00:00:00Z")},
		}
		updated := applyExpirationPolicy(entries, 180)
		expects := []string{"2025-06-30T00:00:00Z", "2026-06-30T00:00:00Z", "2036-01-01T00:00:00Z"}
		for i, exp := range expects {
			if !updated[i].ExpiresAt.Equal(mustParse(t, exp)) {
				t.Errorf("key %s: esperado expires_at %s, obtido %s", updated[i].KeyID, exp, updated[i].ExpiresAt)
			}
		}
	})

	t.Run("Lista vazia não altera nada", func(t *testing.T) {
		entries := []KeyEntry{}
		res := applyExpirationPolicy(entries, 90)
		if len(res) != 0 {
			t.Errorf("esperado lista vazia, obtido %d entradas", len(res))
		}
	})
}

func TestLoadConfigCases(t *testing.T) {
	t.Run("Arquivo inexistente", func(t *testing.T) {
		_, err := loadConfig("naoexiste.yaml")
		if err == nil {
			t.Error("esperado erro de arquivo ausente")
		}
	})
	t.Run("YAML inválido", func(t *testing.T) {
		temp := t.TempDir() + "/bad.yaml"
		os.WriteFile(temp, []byte("{invalid:"), 0644)
		_, err := loadConfig(temp)
		if err == nil {
			t.Error("esperado erro de YAML inválido")
		}
	})
	t.Run("YAML válido", func(t *testing.T) {
		temp := t.TempDir() + "/ok.yaml"
		yaml := `
keys:
  jwt:
    - key_id: "alias/test"
      use_from: "2024-01-01T00:00:00Z"
expires_policy:
  overlap_days: 180`
		os.WriteFile(temp, []byte(yaml), 0644)
		cfg, err := loadConfig(temp)
		if err != nil || len(cfg.Keys["jwt"]) != 1 {
			t.Errorf("erro ao carregar YAML válido: %v", err)
		}
	})
}

func TestLoadKeyGroup_ErrorPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := mocks.NewMockKMSClient(ctrl)
	mock.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(nil, assertError("falha simulada"))

	target := []*KeyHolder{}
	defer func() {
		if r := recover(); r == nil {
			t.Error("esperado panic por erro de GetPublicKey")
		}
	}()

	loadKeyGroup(context.Background(), mock, []KeyEntry{{KeyID: "fail", UseFrom: time.Now()}}, &target)
}

func TestGetSignerAtAndVisible(t *testing.T) {
	now := mustParse(t, "2024-06-01T00:00:00Z")
	entries := []*KeyHolder{
		{keyID: "k1", UseFrom: mustParse(t, "2023-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2023-12-31T00:00:00Z")},
		{keyID: "k2", UseFrom: mustParse(t, "2024-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2025-01-01T00:00:00Z")},
		{keyID: "k3", UseFrom: mustParse(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2026-01-01T00:00:00Z")},
	}
	t.Run("getSignerAt", func(t *testing.T) {
		active := getSignerAt(entries, now)
		if active == nil || active.keyID != "k2" {
			t.Errorf("esperado k2, obtido %v", active.keyID)
		}
	})
	t.Run("getVisibleAt", func(t *testing.T) {
		visible := getVisibleAt(entries, now)
		if len(visible) != 2 || visible[0].keyID != "k2" || visible[1].keyID != "k3" {
			t.Errorf("esperado visíveis [k2 k3], obtido %v", visible)
		}
	})
	t.Run("Nenhuma ativa ou visível", func(t *testing.T) {
		past := mustParse(t, "2010-01-01T00:00:00Z")
		if getSignerAt(entries, past) != nil {
			t.Error("esperado nil em getSignerAt com tempo anterior")
		}
		if len(getVisibleAt(entries, past)) != 3 {
			t.Error("esperado todas visíveis se expiradas no futuro")
		}
	})
}

func assertError(msg string) error {
	return &mockError{msg}
}

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }
