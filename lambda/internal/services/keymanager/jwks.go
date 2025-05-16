package keymanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrConfiguredKeyNotSupported = errors.New("configured key not supported")
	ErrInvalidKey                = errors.New("invalid public key")
	ErrCouldNotSignKey           = errors.New("could not sign key")
)

type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSEntry struct {
	key *KeyHolder
	use string
}

type JWKSConfig struct {
	issuer            string
	expireInHours     int
	skewTimeInSeconds int
}

func NewJWKSEntry(key *KeyHolder, use string) *JWKSEntry {
	return &JWKSEntry{key, use}
}

func NewJWKSConfig(issuer string, expireInHours int, skewTimeInSeconds int) *JWKSConfig {
	return &JWKSConfig{issuer, expireInHours, skewTimeInSeconds}
}

func base64urlUInt(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func base64urlInt(i int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i)).Bytes())
}

func BuildJWKS(
	entries []*JWKSEntry,
	config *JWKSConfig,
	signMethod jwt.SigningMethod,
	signer interface{},
) (string, error) {
	jwkSet, err := BuildJWKSet(entries)
	if err != nil {
		return "", err
	}

	now := time.Now().Add(-time.Duration(config.skewTimeInSeconds) * time.Second)
	exp := now.Add(time.Duration(config.expireInHours) * time.Hour)

	type JWKSClaims struct {
		jwt.RegisteredClaims
		JWKS JWKS `json:"jwks"`
	}

	claims := JWKSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		JWKS: jwkSet,
	}

	token := jwt.NewWithClaims(signMethod, claims)

	signedJWT, err := token.SignedString(signer)
	if err != nil {
		return "", fmt.Errorf("erro ao assinar JWKS: %w", err)
	}

	return signedJWT, nil
}

func BuildJWKSet(entries []*JWKSEntry) (JWKS, error) {
	keys := make([]JWK, 0, len(entries))

	for _, pair := range entries {
		pubKey, err := x509.ParsePKIXPublicKey(pair.key.PubKey.PublicKey)
		if err != nil {
			return JWKS{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}

		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pair.key.PubKey.PublicKey})
		cert := base64.StdEncoding.EncodeToString(pemBlock)

		switch pub := pubKey.(type) {
		case *rsa.PublicKey:
			keys = append(keys, JWK{
				Kty: "RSA",
				Kid: pair.key.Kid(),
				Use: pair.use,
				Alg: "RS256",
				N:   base64urlUInt(pub.N),
				E:   base64urlInt(pub.E),
				X5c: []string{cert},
			})
		case *ecdsa.PublicKey:
			curve := pub.Curve.Params().Name
			alg := map[string]string{
				"P-256": "ES256",
				"P-384": "ES384",
				"P-521": "ES512",
			}[curve]
			if alg == "" {
				return JWKS{}, fmt.Errorf("curva EC não suportada: %s", curve)
			}

			keys = append(keys, JWK{
				Kty: "EC",
				Kid: pair.key.Kid(),
				Use: pair.use,
				Alg: alg,
				Crv: curve,
				X:   base64urlUInt(pub.X),
				Y:   base64urlUInt(pub.Y),
				X5c: []string{cert},
			})
		default:
			return JWKS{}, ErrConfiguredKeyNotSupported
		}
	}

	return JWKS{Keys: keys}, nil
}
