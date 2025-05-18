package keymanager

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v3"
)

type KeyEntry struct {
	KeyID     string    `yaml:"key_id"`
	UseFrom   time.Time `yaml:"use_from"`
	ExpiresAt time.Time `yaml:"-"` // calculado automaticamente
}

type Config struct {
	Issuer        string                `yaml:"issuer"`
	Keys          map[string][]KeyEntry `yaml:"keys"`
	ExpiresPolicy struct {
		OverlapDays int `yaml:"overlap_days"`
	} `yaml:"expires_policy"`
}

// LoadConfig lê o YAML com as configurações das chaves
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
