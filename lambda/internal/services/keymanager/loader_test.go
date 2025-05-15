package keymanager

import (
	"context"
	"lambda-ca-kms/mocks"
	"os"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
)

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

func assertError(msg string) error {
	return &mockError{msg}
}

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }
