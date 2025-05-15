package keymanager

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"gopkg.in/yaml.v3"
)

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
	JWTKeys  []*KeyHolder
	JOSEKeys []*KeyHolder
	JWKSKeys []*KeyHolder
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
func loadKeyGroup(ctx context.Context, client jwtkms.KMSClient, entries []KeyEntry, target *[]*KeyHolder) {
	for _, entry := range entries {
		pubKey, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: &entry.KeyID,
		})
		must(err)

		cfg := jwtkms.NewKMSConfig(client, entry.KeyID, false)

		kw := NewKeyHolder(pubKey, cfg, entry)
		*target = append(*target, kw)
	}
}

// Alias para uso direto
func GetJWTSigner() *KeyHolder  { return getSignerAt(JWTKeys, time.Now()) }
func GetJOSESigner() *KeyHolder { return getSignerAt(JOSEKeys, time.Now()) }
func GetJWKSSigner() *KeyHolder { return getSignerAt(JWKSKeys, time.Now()) }

func GetJWTKeysForJWKS() []*KeyHolder  { return getVisibleAt(JWTKeys, time.Now()) }
func GetJOSEKeysForJWKS() []*KeyHolder { return getVisibleAt(JOSEKeys, time.Now()) }
func GetJWKSKeysForJWKS() []*KeyHolder { return getVisibleAt(JWKSKeys, time.Now()) }
