package keymanager

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"time"
)

// Estrutura que empacota uma chave do KMS
type KeyHolder struct {
	config    *jwtkms.Config
	PubKey    *kms.GetPublicKeyOutput
	keyID     string
	UseFrom   time.Time
	ExpiresAt time.Time
}

// Métodos auxiliares para assinatura
func (k *KeyHolder) WithContext(ctx context.Context) *jwtkms.Config {
	return k.config.WithContext(ctx)
}

func (k *KeyHolder) SigningMethod() *jwtkms.KMSSigningMethod {
	switch k.PubKey.KeySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		return jwtkms.SigningMethodPS256
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1:
		return jwtkms.SigningMethodECDSA256
	default:
		return nil
	}
}
func (k *KeyHolder) KeyId() string {
	return *k.PubKey.KeyId
}
func (k *KeyHolder) Kid() string {
	raw := *k.PubKey.KeyId

	hash := sha256.Sum256([]byte(raw))

	// base64url encoding, sem padding
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	// retorna apenas os primeiros 32 caracteres (opcional: reduzir tamanho mantendo unicidade razoável)
	return encoded[:32]
}

func NewKeyHolder(pub *kms.GetPublicKeyOutput, cfg *jwtkms.Config, entry KeyEntry) *KeyHolder {
	return &KeyHolder{
		config:    cfg,
		keyID:     entry.KeyID,
		PubKey:    pub,
		UseFrom:   entry.UseFrom,
		ExpiresAt: entry.ExpiresAt,
	}
}
