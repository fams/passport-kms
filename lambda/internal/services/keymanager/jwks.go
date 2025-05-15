package keymanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

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

func NewJWKSEntry(key *KeyHolder, use string) *JWKSEntry {
	return &JWKSEntry{key, use}
}

type JWKSEntry struct {
	key *KeyHolder
	use string
}

func NewJWKSConfig(issuer string, expireInHours int, skewTimeInSeconds int) *JWKSConfig {
	return &JWKSConfig{issuer, expireInHours, skewTimeInSeconds}
}

type JWKSConfig struct {
	issuer            string
	expireInHours     int
	skewTimeInSeconds int
}

func base64urlUInt(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func base64urlInt(i int) string {
	buf := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(buf)
}

func BuildJWKS(ctx context.Context, entries []*JWKSEntry, config *JWKSConfig, jwksSigner *KeyHolder) (string, error) {
	var keys []JWK

	for _, pair := range entries {
		pub, err := x509.ParsePKIXPublicKey(pair.key.PubKey.PublicKey)
		if err != nil {
			return "", errors.Join(ErrInvalidKey, err)
		}

		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pair.key.PubKey.PublicKey})
		cert := base64.StdEncoding.EncodeToString(pemBlock)

		switch pub := pub.(type) {
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
			alg := "ES256"
			if curve == "P-384" {
				alg = "ES384"
			} else if curve == "P-521" {
				alg = "ES512"
			}

			keys = append(keys, JWK{
				Kty: "EC",
				Kid: pair.key.Kid(),
				Use: pair.use,
				Alg: alg,
				Crv: curve,
				X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
				X5c: []string{cert},
			})
		default:
			return "", ErrConfiguredKeyNotSupported
		}
	}

	jwks := JWKS{Keys: keys}
	now := time.Now().Add(-time.Duration(config.skewTimeInSeconds) * time.Second)
	claims := jwt.RegisteredClaims{
		Issuer:    config.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(6 * time.Hour)),
	}

	type JWKSClaims struct {
		jwt.RegisteredClaims
		JWKS JWKS `json:"jwks"`
	}

	customClaims := JWKSClaims{
		RegisteredClaims: claims,
		JWKS:             jwks,
	}

	token := jwt.NewWithClaims(jwksSigner.SigningMethod(), customClaims)

	signedJWT, err := token.SignedString(jwksSigner.WithContext(ctx))
	if err != nil {
		return "", errors.Join(ErrCouldNotSignKey, err)
	}

	return signedJWT, nil
}
