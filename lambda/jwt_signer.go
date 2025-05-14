package main

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func SignJWT(signer *KMSSigner, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = signer.KeyID
	signed, err := token.SignedString(&KMSPrivateKey{signer})
	return signed, err
}
