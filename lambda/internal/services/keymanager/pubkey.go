package keymanager

import (
	"encoding/pem"
)

func GetPublicKey() ([]byte, error) {
	out := GetJWKSSigner().PubKey
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: out.PublicKey})
	return pemBlock, nil
}
