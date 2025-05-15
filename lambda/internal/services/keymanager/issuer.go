package keymanager

import (
	"encoding/json"
	"fmt"
)

type kidMap map[string]string
type issuerConfig struct {
	Issuer         string `json:"issuer"`
	SigningKeys    kidMap `json:"signing_keys"`
	DecriptionKeys kidMap `json:"decryption_keys"`
}

func buildIssuerConfig(signKeys []*KeyHolder, joseKey *KeyHolder) ([]byte, error) {
	dks := make(kidMap, len(signKeys))
	for i, v := range JWKSKeys {
		dks[v.Kid()] = JWKSKeys[i].KeyId()
	}

	conf := &issuerConfig{
		Issuer:         fmt.Sprintf("https://%s", "TESTE"),
		SigningKeys:    kidMap{joseKey.Kid(): joseKey.KeyId()},
		DecriptionKeys: dks,
	}
	return json.Marshal(conf)
}
