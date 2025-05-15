package keymanager

import (
	"context"
	"encoding/pem"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"

	"lambda-ca-kms/internal/entities/services"
	"time"
)

type keyManager struct {
	jwtKeys           []*KeyHolder
	joseKeys          []*KeyHolder
	jwksKeys          []*KeyHolder
	issuer            string
	expireInHours     int
	skewTimeInSeconds int
}

var _ services.KeyManager = (*keyManager)(nil)

func (k *keyManager) JWKSCurrent(ctx context.Context) (string, error) {
	entries := make([]*JWKSEntry, len(k.jwksKeys)+1)
	entries[0] = &JWKSEntry{GetSignerAt(k.joseKeys, time.Now()), "enc"}
	for i := range GetVisibleAt(k.jwtKeys, time.Now()) {
		entries[i+1] = &JWKSEntry{GetSignerAt(k.jwtKeys, time.Now()), "sig"}
	}

	return BuildJWKS(ctx, entries, &JWKSConfig{
		issuer:            k.issuer,
		expireInHours:     k.expireInHours,
		skewTimeInSeconds: k.skewTimeInSeconds,
	}, GetSignerAt(k.jwksKeys, time.Now()))

}

func (k *keyManager) JWKSPublicKey(ctx context.Context) ([]byte, error) {
	out := GetSignerAt(k.jwksKeys, time.Now()).PubKey
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return pemBlock, nil
}

func (k *keyManager) IssuerConfig(ctx context.Context) ([]byte, error) {
	return buildIssuerConfig(
		GetVisibleAt(k.jwtKeys, time.Now()),
		GetSignerAt(k.jwksKeys, time.Now()))
}

func NewKeyManager(ctx context.Context, kmsClient *kms.Client, cfg *Config) (*keyManager, error) {
	jwtKeyGroup, err := fillKeyGroup(ctx, kmsClient, ApplyExpirationPolicy(cfg.Keys["jwt"], cfg.ExpiresPolicy.OverlapDays))
	if err != nil {
		return nil, err
	}
	joseKeyGroup, err := fillKeyGroup(ctx, kmsClient, ApplyExpirationPolicy(cfg.Keys["jose"], cfg.ExpiresPolicy.OverlapDays))
	if err != nil {
		return nil, err
	}
	jwksKeyGroup, err := fillKeyGroup(ctx, kmsClient, ApplyExpirationPolicy(cfg.Keys["jwks"], cfg.ExpiresPolicy.OverlapDays))
	if err != nil {
		return nil, err
	}
	km := &keyManager{
		jwtKeys:  jwtKeyGroup,
		joseKeys: joseKeyGroup,
		jwksKeys: jwksKeyGroup,
	}
	return km, nil
}

func fillKeyGroup(ctx context.Context, client jwtkms.KMSClient, entries []KeyEntry) ([]*KeyHolder, error) {
	keyGroup := []*KeyHolder{}
	for _, entry := range entries {
		pubKey, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: &entry.KeyID,
		})
		if err != nil {
			return nil, err
		}
		cfg := jwtkms.NewKMSConfig(client, entry.KeyID, false)

		kw := NewKeyHolder(pubKey, cfg, entry)
		keyGroup = append(keyGroup, kw)
	}
	return keyGroup, nil
}

// Recupera a chave ativa no momento
func GetSignerAt(keys []*KeyHolder, now time.Time) *KeyHolder {
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

func ApplyExpirationPolicy(entries []KeyEntry, overlapDays int) []KeyEntry {
	if len(entries) == 0 {
		return entries
	}
	for i := 0; i < len(entries)-1; i++ {
		nextUse := entries[i+1].UseFrom
		entries[i].ExpiresAt = nextUse.AddDate(0, 0, overlapDays)
	}
	entries[len(entries)-1].ExpiresAt = entries[len(entries)-1].UseFrom.AddDate(10, 0, 0) // default: 10 anos
	return entries
}

// Representa uma entrada de chave no YAML
type KeyEntry struct {
	KeyID     string    `yaml:"key_id"`
	UseFrom   time.Time `yaml:"use_from"`
	ExpiresAt time.Time `yaml:"-"` // calculado automaticamente
}

// Configuração do YAML
type Config struct {
	Issuer        string                `yaml:"issuer"`
	Keys          map[string][]KeyEntry `yaml:"keys"`
	ExpiresPolicy struct {
		OverlapDays int `yaml:"overlap_days"`
	} `yaml:"expires_policy"`
}
