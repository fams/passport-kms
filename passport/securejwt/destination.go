package securejwt

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type Destination struct {
	Audience string
	KID      string
	JWKSURL  string
}

type DestinationResolver interface {
	Resolve(name string) (Destination, error)
}

type DestinationSource interface {
	Load(name string) (Destination, error)
}

type cachedDestination struct {
	value     Destination
	expiresAt time.Time
}

type CachingDestinationResolver struct {
	source DestinationSource
	cache  map[string]cachedDestination
	ttl    time.Duration
	mu     sync.RWMutex
}

func NewCachingDestinationResolver(source DestinationSource, ttl time.Duration) *CachingDestinationResolver {
	return &CachingDestinationResolver{
		source: source,
		cache:  make(map[string]cachedDestination),
		ttl:    ttl,
	}
}

func (r *CachingDestinationResolver) Resolve(name string) (Destination, error) {
	now := time.Now()

	r.mu.RLock()
	if entry, ok := r.cache[name]; ok {
		if now.Before(entry.expiresAt) {
			defer r.mu.RUnlock()
			return entry.value, nil
		}
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.cache[name]; ok && now.Before(entry.expiresAt) {
		return entry.value, nil
	}

	dest, err := r.source.Load(name)
	if err != nil {
		return Destination{}, fmt.Errorf("não foi possível carregar destino '%s': %w", name, err)
	}

	r.cache[name] = cachedDestination{
		value:     dest,
		expiresAt: now.Add(r.ttl),
	}

	return dest, nil
}

type StaticSource struct {
	store map[string]Destination
}

func NewStaticSource() *StaticSource {
	return &StaticSource{store: make(map[string]Destination)}
}

func (s *StaticSource) Register(name string, d Destination) {
	s.store[name] = d
}

func (s *StaticSource) Load(name string) (Destination, error) {
	d, ok := s.store[name]
	if !ok {
		return Destination{}, errors.New("destino não encontrado")
	}
	return d, nil
}
