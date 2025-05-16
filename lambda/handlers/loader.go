package handlers

import (
	"context"
	"encoding/pem"
	"io/ioutil"
	"lambda-ca-kms/internal/services/keymanager"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
	"gopkg.in/yaml.v3"
)

// Carrega a configuração YAML
func loadConfig(path string) (*keymanager.Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg keymanager.Config
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
	JWTKeys  []*keymanager.KeyHolder
	JOSEKeys []*keymanager.KeyHolder
	JWKSKeys []*keymanager.KeyHolder
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

	loadKeyGroup(ctx, realClient, keymanager.ApplyExpirationPolicy(conf.Keys["jwt"], days), &JWTKeys)
	loadKeyGroup(ctx, realClient, keymanager.ApplyExpirationPolicy(conf.Keys["jose"], days), &JOSEKeys)
	loadKeyGroup(ctx, realClient, keymanager.ApplyExpirationPolicy(conf.Keys["jwks"], days), &JWKSKeys)
}

// Agora espera o cliente real e também é compatível com a interface
func loadKeyGroup(ctx context.Context, client jwtkms.KMSClient, entries []keymanager.KeyEntry, target *[]*keymanager.KeyHolder) {
	for _, entry := range entries {
		pubKey, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: &entry.KeyID,
		})
		must(err)

		cfg := jwtkms.NewKMSConfig(client, entry.KeyID, false)

		kw := keymanager.NewKeyHolder(pubKey, cfg, entry)
		*target = append(*target, kw)
	}
}

// Alias para uso direto
func GetJWTSigner() *keymanager.KeyHolder  { return keymanager.GetActiveKey(JWTKeys, time.Now()) }
func GetJOSESigner() *keymanager.KeyHolder { return keymanager.GetActiveKey(JOSEKeys, time.Now()) }
func GetJWKSSigner() *keymanager.KeyHolder { return keymanager.GetActiveKey(JWKSKeys, time.Now()) }

func GetJWTKeysForJWKS() []*keymanager.KeyHolder { return keymanager.GetVisibleAt(JWTKeys, time.Now()) }
func GetJOSEKeysForJWKS() []*keymanager.KeyHolder {
	return keymanager.GetVisibleAt(JOSEKeys, time.Now())
}
func GetJWKSKeysForJWKS() []*keymanager.KeyHolder {
	return keymanager.GetVisibleAt(JWKSKeys, time.Now())
}

func GetJWKS(ctx context.Context) (string, error) {
	entries := []*keymanager.JWKSEntry{
		keymanager.NewJWKSEntry(GetJWTSigner(), "sig"),
		keymanager.NewJWKSEntry(GetJOSESigner(), "enc"),
	}
	return keymanager.BuildJWKS(entries, keymanager.NewJWKSConfig(
		"jwks.ca.internal",
		24,
		300), GetJWTSigner().SigningMethod(), GetJWKSSigner().WithContext(ctx))
}

func GetPublicKey() ([]byte, error) {
	out := GetJWKSSigner().PubKey
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return pemBlock, nil
}
