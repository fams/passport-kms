package keymanager

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"gopkg.in/yaml.v3"
)

// Interface para facilitar testes com gomock
type KMSClient interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// Representa uma entrada de chave no YAML
type KeyEntry struct {
	KeyID     string    `yaml:"key_id"`
	UseFrom   time.Time `yaml:"use_from"`
	ExpiresAt time.Time `yaml:"-"` // calculado automaticamente
}

// Configuração do YAML
type Config struct {
	Keys          map[string][]KeyEntry `yaml:"keys"`
	ExpiresPolicy struct {
		OverlapDays int `yaml:"overlap_days"`
	} `yaml:"expires_policy"`
}

// Estrutura que empacota uma chave do KMS
type KeyWrapper struct {
	config    *jwtkms.Config
	PubKey    *kms.GetPublicKeyOutput
	keyID     string
	UseFrom   time.Time
	ExpiresAt time.Time
}

// Métodos auxiliares para assinatura
func (k *KeyWrapper) WithContext(ctx context.Context) *jwtkms.Config {
	return k.config.WithContext(ctx)
}

func (k *KeyWrapper) SigningMethod() *jwtkms.KMSSigningMethod {
	switch k.PubKey.KeySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		return jwtkms.SigningMethodPS256
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1:
		return jwtkms.SigningMethodECDSA256
	default:
		return nil
	}
}

func (k *KeyWrapper) Kid() string {
	raw := *k.PubKey.KeyId

	hash := sha256.Sum256([]byte(raw))

	// base64url encoding, sem padding
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	// retorna apenas os primeiros 32 caracteres (opcional: reduzir tamanho mantendo unicidade razoável)
	return encoded[:32]
}

// Nova versão — não faz cast, apenas empacota valores
func NewKeyWrapper(pub *kms.GetPublicKeyOutput, cfg *jwtkms.Config, entry KeyEntry) *KeyWrapper {
	return &KeyWrapper{
		config:    cfg,
		keyID:     entry.KeyID,
		PubKey:    pub,
		UseFrom:   entry.UseFrom,
		ExpiresAt: entry.ExpiresAt,
	}
}

// Aplica a política de expiração com overlap entre chaves
func applyExpirationPolicy(entries []KeyEntry, overlapDays int) []KeyEntry {
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

// Carrega a configuração YAML
func loadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Variáveis globais com as chaves organizadas por finalidade
var (
	JWTKeys  []*KeyWrapper
	JOSEKeys []*KeyWrapper
	JWKSKeys []*KeyWrapper
)

// Ponto de entrada principal para carregar todas as chaves
func InitKMS() {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	must(err)

	realClient := kms.NewFromConfig(cfg)

	configPath := os.Getenv("KMS_CONFIG_PATH")
	if configPath == "" {
		configPath = "config/kms-keys.yaml"
	}
	conf, err := loadConfig(configPath)
	must(err)

	days := conf.ExpiresPolicy.OverlapDays

	loadKeyGroup(ctx, realClient, applyExpirationPolicy(conf.Keys["jwt"], days), &JWTKeys)
	loadKeyGroup(ctx, realClient, applyExpirationPolicy(conf.Keys["jose"], days), &JOSEKeys)
	loadKeyGroup(ctx, realClient, applyExpirationPolicy(conf.Keys["jwks"], days), &JWKSKeys)
}

// Agora espera o cliente real e também é compatível com a interface
func loadKeyGroup(ctx context.Context, client jwtkms.KMSClient, entries []KeyEntry, target *[]*KeyWrapper) {
	for _, entry := range entries {
		pubKey, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: &entry.KeyID,
		})
		must(err)

		cfg := jwtkms.NewKMSConfig(client, entry.KeyID, false)

		kw := NewKeyWrapper(pubKey, cfg, entry)
		*target = append(*target, kw)
	}
}

// Recupera a chave ativa no momento
func GetSignerAt(keys []*KeyWrapper, now time.Time) *KeyWrapper {
	var active *KeyWrapper
	for _, k := range keys {
		if (k.UseFrom.Before(now) || k.UseFrom.Equal(now)) &&
			(active == nil || k.UseFrom.After(active.UseFrom)) {
			active = k
		}
	}
	return active
}

// Recupera todas as chaves ainda válidas
func GetVisibleAt(keys []*KeyWrapper, now time.Time) []*KeyWrapper {
	var visible []*KeyWrapper
	for _, k := range keys {
		if k.ExpiresAt.After(now) {
			visible = append(visible, k)
		}
	}
	return visible
}

// Alias para uso direto
func GetJWTSigner() *KeyWrapper  { return GetSignerAt(JWTKeys, time.Now()) }
func GetJOSESigner() *KeyWrapper { return GetSignerAt(JOSEKeys, time.Now()) }
func GetJWKSSigner() *KeyWrapper { return GetSignerAt(JWKSKeys, time.Now()) }

func GetJWTKeysForJWKS() []*KeyWrapper  { return GetVisibleAt(JWTKeys, time.Now()) }
func GetJOSEKeysForJWKS() []*KeyWrapper { return GetVisibleAt(JOSEKeys, time.Now()) }
func GetJWKSKeysForJWKS() []*KeyWrapper { return GetVisibleAt(JWKSKeys, time.Now()) }
