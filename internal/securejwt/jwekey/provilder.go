package jwekey

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

type Provider struct {
	jwksURL   string
	client    *http.Client
	cache     jwk.Set
	ttl       time.Duration
	lastFetch time.Time
	mu        sync.RWMutex
}

func New(jwksURL string, ttl time.Duration) *Provider {
	return &Provider{
		jwksURL: jwksURL,
		client:  &http.Client{Timeout: 5 * time.Second},
		ttl:     ttl,
	}
}

func (p *Provider) GetPublicKeyByKID(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.RLock()
	if time.Since(p.lastFetch) < p.ttl && p.cache != nil {
		defer p.mu.RUnlock()
		return p.extractKey(kid)
	}
	p.mu.RUnlock()

	return p.refresh(ctx, kid)
}

func (p *Provider) refresh(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	set, err := jwk.Fetch(ctx, p.jwksURL, jwk.WithHTTPClient(p.client))
	if err != nil {
		return nil, fmt.Errorf("falha ao buscar JWKS: %w", err)
	}
	p.cache = set
	p.lastFetch = time.Now()

	return p.extractKey(kid)
}

func (p *Provider) extractKey(kid string) (crypto.PublicKey, error) {
	key, found := p.cache.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("nenhuma chave encontrada para kid: %s", kid)
	}

	key, ok := key.(jwk.RSAPublicKey)
	if !ok {
		return nil, errors.New("a chave recuperada não é do tipo RSA")
	}

	var pubKey crypto.PublicKey
	if err := key.Raw(&pubKey); err != nil {
		return nil, fmt.Errorf("erro ao extrair chave pública: %w", err)
	}
	return pubKey, nil
}
