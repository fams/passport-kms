package keymanager

import (
	"testing"
	"time"
)

func TestGetSignerAtAndVisible(t *testing.T) {
	now := mustParse(t, "2024-06-01T00:00:00Z")
	entries := []*KeyHolder{
		{keyID: "k1", UseFrom: mustParse(t, "2023-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2023-12-31T00:00:00Z")},
		{keyID: "k2", UseFrom: mustParse(t, "2024-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2025-01-01T00:00:00Z")},
		{keyID: "k3", UseFrom: mustParse(t, "2025-01-01T00:00:00Z"), ExpiresAt: mustParse(t, "2026-01-01T00:00:00Z")},
	}
	t.Run("GetActiveKey", func(t *testing.T) {
		active := GetActiveKey(entries, now)
		if active == nil || active.keyID != "k2" {
			t.Errorf("esperado k2, obtido %v", active.keyID)
		}
	})
	t.Run("GetVisibleAt", func(t *testing.T) {
		visible := GetVisibleAt(entries, now)
		if len(visible) != 2 || visible[0].keyID != "k2" || visible[1].keyID != "k3" {
			t.Errorf("esperado visíveis [k2 k3], obtido %v", visible)
		}
	})
	t.Run("Nenhuma ativa ou visível", func(t *testing.T) {
		past := mustParse(t, "2010-01-01T00:00:00Z")
		if GetActiveKey(entries, past) != nil {
			t.Error("esperado nil em GetActiveKey com tempo anterior")
		}
		if len(GetVisibleAt(entries, past)) != 3 {
			t.Error("esperado todas visíveis se expiradas no futuro")
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
		updated := ApplyExpirationPolicy(entries, 180)
		expects := []string{"2025-06-30T00:00:00Z", "2026-06-30T00:00:00Z", "2036-01-01T00:00:00Z"}
		for i, exp := range expects {
			if !updated[i].ExpiresAt.Equal(mustParse(t, exp)) {
				t.Errorf("key %s: esperado expires_at %s, obtido %s", updated[i].KeyID, exp, updated[i].ExpiresAt)
			}
		}
	})

	t.Run("Lista vazia não altera nada", func(t *testing.T) {
		entries := []KeyEntry{}
		res := ApplyExpirationPolicy(entries, 90)
		if len(res) != 0 {
			t.Errorf("esperado lista vazia, obtido %d entradas", len(res))
		}
	})
}

func mustParse(t *testing.T, s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("erro ao parsear tempo: %v", err)
	}
	return tm
}
