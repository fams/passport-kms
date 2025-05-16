package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestJWKSCurrent_ComRotacaoTemporal(t *testing.T) {
	//	ctx := context.Background()

	// Criar chave ECDSA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER2, _ := x509.MarshalPKIXPublicKey(&priv2.PublicKey)
	kid := "k1"
	kid2 := "k2"
	joseKidNow := "joseNow"
	joseKidFuture := "joseFuture"
	jwksId1 := "jwksid"
	// Simular clock controlado
	var now time.Time = mustParse(t, "2025-01-01T00:00:00Z")
	myClock := MockClock(now)

	// ✅ joseKey: ativa só depois de 2 dias (enc)
	joseKeyNow := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER, KeyId: &joseKidNow},
		UseFrom:   mustParse(t, "2024-01-01T00:00:00Z"),
		ExpiresAt: mustParse(t, "2030-01-01T00:00:00Z"),
	}
	// ✅ joseKey: ativa só depois de 2 dias (enc)
	joseKeyFuture := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER, KeyId: &joseKidFuture},
		UseFrom:   mustParse(t, "2025-01-03T00:00:00Z"),
		ExpiresAt: mustParse(t, "2030-01-01T00:00:00Z"),
	}

	// ✅ jwtKey1: já ativa (sig)
	jwtKey1 := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER, KeyId: &kid},
		UseFrom:   mustParse(t, "2024-12-01T00:00:00Z"),
		ExpiresAt: mustParse(t, "2026-01-01T00:00:00Z"),
	}

	// ✅ jwtKey2: só ativa depois de 1 dia (sig)
	jwtKey2 := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER2, KeyId: &kid2},
		UseFrom:   mustParse(t, "2025-01-02T00:00:00Z"),
		ExpiresAt: mustParse(t, "2026-01-01T00:00:00Z"),
	}

	// ✅ jwksSigner: ativa desde sempre
	jwksKey := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER2, KeyId: &jwksId1},
		UseFrom:   mustParse(t, "2024-01-01T00:00:00Z"),
		ExpiresAt: mustParse(t, "2028-01-01T00:00:00Z"),
	}

	// Criar instância manual de keyManager
	k := &keyManager{
		joseKeys:          []*KeyHolder{joseKeyFuture, joseKeyNow},
		jwtKeys:           []*KeyHolder{jwtKey1, jwtKey2},
		jwksKeys:          []*KeyHolder{jwksKey},
		issuer:            "https://issuer.example",
		expireInHours:     12,
		skewTimeInSeconds: 0,
		clock:             myClock,
	}

	// ▶️ Etapa 1: agora = 2025-01-01 → apenas jwtKey1 deve estar visível, e joseKey ainda não ativa
	entries, _ := k.currentKeys()
	jwks1, err := BuildJWKSet(entries)
	if err != nil {
		t.Fatalf("erro ao gerar jwks etapa 1: %v", err)
	}
	if len(jwks1.Keys) != 2 {
		t.Errorf("esperado 1 sig + 1 enc (mesmo inativo), obtido %d", len(jwks1.Keys))
	}
	if countByUse(jwks1.Keys, "sig") != 1 {
		t.Errorf("esperado 1 chave 'sig', obtido %d", countByUse(jwks1.Keys, "sig"))
	}
	if countByUse(jwks1.Keys, "enc") != 0 {
		t.Errorf("esperado 0 chave 'enc' ativa, obtido %d", countByUse(jwks1.Keys, "enc"))
	}

	// ▶️ Etapa 2: avançar para 2025-01-03 → todas as chaves devem aparecer
	now = mustParse(t, "2025-01-03T00:00:00Z")
	myClock.SetTime(now)
	entries, _ = k.currentKeys()
	jwks2, err := BuildJWKSet(entries)
	if err != nil {
		t.Fatalf("erro ao gerar jwks etapa 2: %v", err)
	}
	if countByUse(jwks2.Keys, "sig") != 2 {
		t.Errorf("esperado 2 chaves 'sig' visíveis, obtido %d", countByUse(jwks2.Keys, "sig"))
	}
	if countByUse(jwks2.Keys, "enc") != 1 {
		t.Errorf("esperado 1 chave 'enc' ativa, obtido %d", countByUse(jwks2.Keys, "enc"))
	}
}

// utilitário para contar chaves por uso
func countByUse(keys []JWK, uso string) int {
	count := 0
	for _, k := range keys {
		if k.Use == uso {
			count++
		}
	}
	return count
}
