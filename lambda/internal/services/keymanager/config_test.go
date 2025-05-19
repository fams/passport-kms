package keymanager

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	temp := t.TempDir()
	file := temp + "/config.yaml"

	yaml := `
issuer: "https://issuer.test"
keys:
  jwt:
    - key_id: "alias/test"
      use_from: "2024-01-01T00:00:00Z"
expires_policy:
  overlap_days: 180
`
	os.WriteFile(file, []byte(yaml), 0644)
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatalf("erro ao carregar YAML válido: %v", err)
	}
	if cfg.Issuer != "https://issuer.test" {
		t.Error("issuer inválido")
	}
}
