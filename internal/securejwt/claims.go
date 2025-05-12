package securejwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

type ClaimsConfig struct {
	Issuer    string
	Audience  string
	Lifetime  time.Duration
	ClockSkew time.Duration
}

type ClaimsBuilder struct {
	config ClaimsConfig
}

func NewClaimsBuilder(cfg ClaimsConfig) *ClaimsBuilder {
	return &ClaimsBuilder{config: cfg}
}

func (b *ClaimsBuilder) BuildClaims(custom map[string]interface{}) (map[string]interface{}, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar jti: %w", err)
	}

	claims := map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Add(b.config.Lifetime).Unix(),
		"nbf": now.Add(-b.config.ClockSkew).Unix(),
		"jti": jti,
		"iss": b.config.Issuer,
	}

	for k, v := range custom {
		claims[k] = v
	}

	return claims, nil
}

func generateJTI() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
