package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
	"lambda-ca-kms/keymanager"
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

func base64urlUInt(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func base64urlInt(i int) string {
	buf := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(buf)
}

func HandleGetJWKS(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var keys []JWK

	for _, pair := range []struct {
		key *keymanager.KeyWrapper
		use string
	}{
		{keymanager.GetJWTSigner(), "sig"},
		{keymanager.GetJOSESigner(), "enc"},
	} {
		pub, err := x509.ParsePKIXPublicKey(pair.key.PubKey.PublicKey)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao decodificar chave pública"}, nil
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
			return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "chave pública com tipo não suportado"}, nil
		}
	}

	jwks := JWKS{Keys: keys}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "jwks.ca.internal",
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

	token := jwt.NewWithClaims(keymanager.GetJWKSSigner().SigningMethod(), customClaims)

	signedJWT, err := token.SignedString(keymanager.GetJWKSSigner().WithContext(ctx))
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: "erro ao assinar JWKS"}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/jwt"},
		Body:       signedJWT,
	}, nil
}
