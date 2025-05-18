package keymanager

import (
	"context"
	"encoding/pem"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"

	"lambda-ca-kms/internal/entities/services"
)

type keyManager struct {
	jwtKeys           []*KeyHolder
	joseKeys          []*KeyHolder
	jwksKeys          []*KeyHolder
	issuer            string
	expireInHours     int
	skewTimeInSeconds int
	clock             Clock
}

var _ services.KeyManager = (*keyManager)(nil)

func (k *keyManager) JWKSCurrent(ctx context.Context) (string, error) {
	entries, jwksSigner := currentKeys(k.jwtKeys, k.joseKeys, k.jwksKeys, k.clock)
	return BuildJWKS(entries, &JWKSConfig{
		issuer:            k.issuer,
		expireInHours:     k.expireInHours,
		skewTimeInSeconds: k.skewTimeInSeconds,
	}, jwksSigner.SigningMethod(), jwksSigner.WithContext(ctx))
}

func (k *keyManager) JWKSPublicKey(ctx context.Context) ([]byte, error) {
	out := GetActiveKey(k.jwksKeys, k.clock.Now()).PubKey
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return pemBlock, nil
}

func (k *keyManager) IssuerConfig(ctx context.Context) ([]byte, error) {
	return buildIssuerConfig(
		GetVisibleAt(k.jwtKeys, k.clock.Now()),
		GetActiveKey(k.jwksKeys, k.clock.Now()))
}

func (k *keyManager) SignJWT(ctx context.Context, claims map[string]interface{}) (string, error) {
	signer := GetActiveKey(k.jwtKeys, k.clock.Now())
	if signer == nil {
		return "", errors.New("nenhuma chave ativa disponível")
	}
	token := jwt.NewWithClaims(signer.SigningMethod(), jwt.MapClaims(claims))
	return token.SignedString(signer.WithContext(ctx))
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
		jwtKeys:           jwtKeyGroup,
		joseKeys:          joseKeyGroup,
		jwksKeys:          jwksKeyGroup,
		issuer:            cfg.Issuer,
		expireInHours:     24,
		skewTimeInSeconds: 300,
		clock:             ReealClock(),
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
