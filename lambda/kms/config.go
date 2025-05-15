package kms

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/matelang/jwt-go-aws-kms/v2/jwtkms"
)

var (
	JWTKeyID  string
	JOSEKeyID string
	JWKSKeyID string

	JWTSigner  *KeyWrapper
	JOSESigner *KeyWrapper
	JWKSSigner *KeyWrapper
)

type KeyWrapper struct {
	config *jwtkms.Config
	keyID  string
	PubKey *kms.GetPublicKeyOutput
}

func (k *KeyWrapper) WithContext(ctx context.Context) *jwtkms.Config {
	return k.config.WithContext(ctx)
}
func (k *KeyWrapper) SigningMethod() *jwtkms.KMSSigningMethod {
	var signMethod *jwtkms.KMSSigningMethod
	switch k.PubKey.KeySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		signMethod = jwtkms.SigningMethodPS256
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1:
		signMethod = jwtkms.SigningMethodECDSA256
	default:
		signMethod = nil
	}
	return signMethod
}

func (k *KeyWrapper) Kid() string {
	return *k.PubKey.KeyId
}

func newKeyWrapper(client *kms.Client, keyId string) (*KeyWrapper, error) {

	pubKey, err := client.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: &keyId,
	})
	if err != nil {
		return nil, err
	}

	return &KeyWrapper{config: jwtkms.NewKMSConfig(client, keyId, false), keyID: keyId, PubKey: pubKey}, nil
}

func InitKMS() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic("falha ao carregar configuração AWS")
	}
	client := kms.NewFromConfig(cfg)

	JWTSigner, err = newKeyWrapper(client, JWTKeyID)
	must(err)
	JOSESigner, err = newKeyWrapper(client, JOSEKeyID)
	must(err)
	JWKSSigner, err = newKeyWrapper(client, JWKSKeyID)
	must(err)
}
func must(err error) {
	if err != nil {
		panic("falha ao carregar JWT signing method")
	}
}
