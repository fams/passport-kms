package securejwt

import (
	"context"
	"fmt"
	"time"
)

type TokenIssuer struct {
	issuer     string
	signer     *Signer
	encryptor  *Encryptor
	claims     *ClaimsBuilder
	destLookup DestinationResolver
}

type TokenIssuerConfig struct {
	Issuer        string
	KMSKeyID      string
	TokenLifetime time.Duration
	ClockSkew     time.Duration
	Destinations  DestinationResolver
}

func NewTokenIssuer(cfg TokenIssuerConfig) (*TokenIssuer, error) {
	signer, err := NewSigner(cfg.KMSKeyID)
	if err != nil {
		return nil, err
	}

	claims := NewClaimsBuilder(ClaimsConfig{
		Issuer:    cfg.Issuer,
		Lifetime:  cfg.TokenLifetime,
		ClockSkew: cfg.ClockSkew,
	})

	return &TokenIssuer{
		issuer:     cfg.Issuer,
		signer:     signer,
		encryptor:  NewEncryptor(),
		claims:     claims,
		destLookup: cfg.Destinations,
	}, nil
}

func (ti *TokenIssuer) Emit(ctx context.Context, customClaims map[string]interface{}, destRef string) (string, error) {
	dest, err := ti.destLookup.Resolve(destRef)
	if err != nil {
		return "", fmt.Errorf("erro ao resolver destino '%s': %w", destRef, err)
	}

	fullClaims, err := ti.claims.BuildClaims(customClaims)
	if err != nil {
		return "", err
	}
	fullClaims["aud"] = dest.Audience

	signedJWT, err := ti.signer.SignJWT(fullClaims)
	if err != nil {
		return "", err
	}

	return ti.encryptor.EncryptJWT(ctx, signedJWT, dest)
}
