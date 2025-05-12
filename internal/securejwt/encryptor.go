package securejwt

import (
	"context"
	//"crypto"
	//"crypto/rsa"
	//"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	//"github.com/lestrrat-go/jwx/v2/jwk"

	"ige/internal/securejwt/jwekey"
)

type Encryptor struct{}

func NewEncryptor() *Encryptor {
	return &Encryptor{}
}
func (e *Encryptor) EncryptJWT(ctx context.Context, signedJWT string, dest Destination) (string, error) {
	provider := jwekey.New(dest.JWKSURL, 10*time.Minute)

	pubKey, err := provider.GetPublicKeyByKID(ctx, dest.KID)
	if err != nil {
		return "", fmt.Errorf("erro ao obter chave pública: %w", err)
	}

	headers := jwe.NewHeaders()
	if err := headers.Set(jwe.ContentTypeKey, "JWT"); err != nil {
		return "", err
	}
	if err := headers.Set(jwe.KeyIDKey, dest.KID); err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(
		[]byte(signedJWT),
		jwe.WithKey(jwa.RSA_OAEP, pubKey),
		jwe.WithContentEncryption(jwa.A256GCM),
		jwe.WithProtectedHeaders(headers),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}
