package handlers

import (
	"context"
	"fmt"
	"os"

	"lambda-ca-kms/internal/entities/services"
	"lambda-ca-kms/internal/services/keymanager"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var manager services.KeyManager

// InitializeKeyManager configura a instância de KeyManager (único ponto de entrada)
func InitializeKeyManager(ctx context.Context) {
	path := os.Getenv("KMS_CONFIG_PATH")
	if path == "" {
		path = "config/kms-keys.yaml"
	}

	cfg, err := keymanager.LoadConfig(path)
	if err != nil {
		panic(fmt.Sprintf("falha ao carregar YAML: %v", err))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(fmt.Sprintf("falha ao carregar AWS config: %v", err))
	}

	client := kms.NewFromConfig(awsCfg)

	m, err := keymanager.NewKeyManager(ctx, client, cfg)
	if err != nil {
		panic(fmt.Sprintf("erro ao inicializar KeyManager: %v", err))
	}

	manager = m
}

// usado internamente para testes
func overrideManager(m services.KeyManager) {
	manager = m
}
