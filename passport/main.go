package main

import (
	"context"
	"fmt"
	"log"
	"passport/securejwt"
	"time"
)

func main() {
	ctx := context.Background()

	destReg := securejwt.NewStaticSource()
	destReg.Register("partnerA", securejwt.Destination{
		Audience: "https://partnerA.app/api",
		KID:      "key-id-a",
		JWKSURL:  "https://partnerA.app/.well-known/jwks.json",
	})
	destReg.Register("partnerB", securejwt.Destination{
		Audience: "https://partnerB.com/receive",
		KID:      "key-id-b",
		JWKSURL:  "https://partnerB.com/jwks",
	})
	resolver := securejwt.NewCachingDestinationResolver(destReg, 10*time.Minute)

	issuer, err := securejwt.NewTokenIssuer(securejwt.TokenIssuerConfig{
		Issuer:        "https://auth.my-service.com",
		KMSKeyID:      "arn:aws:kms:us-east-1:696300981483:alias/jwt-signing",
		TokenLifetime: 5 * time.Minute,
		ClockSkew:     30 * time.Second,
		Destinations:  resolver, // <- passa o resolver, não os destinos diretamente
	})
	if err != nil {
		log.Fatal(err)
	}

	token, err := issuer.Emit(ctx, map[string]interface{}{
		"sub":   "user-xyz",
		"scope": "read:invoice",
	}, "partnerA")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("JWE emitido:", token)
}
