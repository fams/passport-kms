package main

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMSSigner struct {
	Client *kms.Client
	KeyID  string
}

func NewKMSSigner(ctx context.Context, keyID string) (*KMSSigner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg)
	return &KMSSigner{Client: client, KeyID: keyID}, nil
}

func (s *KMSSigner) SignSHA256(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	out, err := s.Client.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.KeyID,
		Message:          hash[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign failed: %w", err)
	}
	return out.Signature, nil
}

func (s *KMSSigner) GetPublicKeyPEM(ctx context.Context) (string, error) {
	out, err := s.Client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &s.KeyID,
	})
	if err != nil {
		return "", err
	}
	return string(out.PublicKey), nil
}
