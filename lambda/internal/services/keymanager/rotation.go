package keymanager

import "time"

// Recupera a chave ativa no momento
func GetActiveKey(keys []*KeyHolder, now time.Time) *KeyHolder {
	var active *KeyHolder
	for _, k := range keys {
		if (k.UseFrom.Before(now) || k.UseFrom.Equal(now)) &&
			(active == nil || k.UseFrom.After(active.UseFrom)) {
			active = k
		}
	}
	return active
}

// Recupera todas as chaves ainda válidas
func GetVisibleAt(keys []*KeyHolder, now time.Time) []*KeyHolder {
	var visible []*KeyHolder
	for _, k := range keys {
		if k.ExpiresAt.After(now) {
			visible = append(visible, k)
		}
	}
	return visible
}

// Aplica a política de expiração com base em overlapDays
func ApplyExpirationPolicy(entries []KeyEntry, overlapDays int) []KeyEntry {
	if len(entries) == 0 {
		return entries
	}
	for i := 0; i < len(entries)-1; i++ {
		nextUse := entries[i+1].UseFrom
		entries[i].ExpiresAt = nextUse.AddDate(0, 0, overlapDays)
	}
	entries[len(entries)-1].ExpiresAt = entries[len(entries)-1].UseFrom.AddDate(10, 0, 0)
	return entries
}

func currentKeys(jwtKeys, joseKeys, jwksKeys []*KeyHolder, clock Clock) ([]*JWKSEntry, *KeyHolder) {
	now := clock.Now()
	visibleKeys := GetVisibleAt(jwtKeys, now)
	entries := make([]*JWKSEntry, len(visibleKeys)+1)
	entries[0] = &JWKSEntry{GetActiveKey(joseKeys, now), "enc"}
	for i := range visibleKeys {
		entries[i+1] = &JWKSEntry{visibleKeys[i], "sig"}
	}
	jwksSigner := GetActiveKey(jwksKeys, now)
	return entries, jwksSigner
}
