package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
)

func TestBuildJWKS_And_SignJWT(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("erro ao gerar chave EC: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("erro ao serializar chave pública: %v", err)
	}

	keyID := "arn:aws:kms:us-east-1:xxxx:key/test"
	holder := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER, KeyId: &keyID},
		UseFrom:   time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	entry := &JWKSEntry{key: holder, use: "sig"}
	cfg := &JWKSConfig{
		issuer:            "https://issuer.test",
		expireInHours:     6,
		skewTimeInSeconds: 0,
	}

	t.Run("BuildJWKS", func(t *testing.T) {
		tokenStr, err := BuildJWKS([]*JWKSEntry{entry}, cfg, jwt.SigningMethodES256, priv)
		if err != nil {
			t.Fatalf("erro ao gerar token JWKS: %v", err)
		}
		parser := jwt.NewParser()
		var claims struct {
			JWKS JWKS `json:"jwks"`
			jwt.RegisteredClaims
		}
		_, err = parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
			return &priv.PublicKey, nil
		})
		if err != nil {
			t.Fatalf("erro ao parsear token: %v", err)
		}
		if len(claims.JWKS.Keys) != 1 {
			t.Error("esperado 1 chave no JWKS")
		}
	})

	t.Run("SignJWT", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":   "1234567890",
			"name":  "John Doe",
			"admin": true,
			"iat":   time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		signed, err := token.SignedString(priv)
		if err != nil {
			t.Fatalf("erro ao assinar JWT: %v", err)
		}
		parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
			return &priv.PublicKey, nil
		})
		if err != nil || !parsed.Valid {
			t.Errorf("JWT inválido: %v", err)
		}
	})
}
