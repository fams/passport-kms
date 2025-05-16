package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestBuildJWKSet(t *testing.T) {
	// Gerar chave RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)

	// Gerar chave EC P-256
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)

	type args struct {
		pubBytes []byte
		use      string
		kty      string
		keyId    string
	}

	tests := []struct {
		name      string
		args      args
		wantError bool
	}{
		{
			name: "Chave RSA válida",
			args: args{
				pubBytes: rsaDER,
				use:      "sig",
				kty:      "RSA",
				keyId:    "aws::kms:/alias/rsa_1_Ok",
			},
			wantError: false,
		},
		{
			name: "Chave EC P-256 válida",
			args: args{
				pubBytes: ecDER,
				use:      "enc",
				kty:      "EC",
				keyId:    "aws::kms:/alias/ecdsa_1_Ok",
			},
			wantError: false,
		},
		{
			name: "Chave inválida (dados corrompidos)",
			args: args{
				pubBytes: []byte("INVALID DATA"),
				use:      "sig",
				keyId:    "aws::kms:/alias/bad",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := &KeyHolder{
				PubKey: &kms.GetPublicKeyOutput{PublicKey: tt.args.pubBytes, KeyId: &tt.args.keyId},
				keyID:  tt.args.keyId,
			}
			entry := &JWKSEntry{
				key: holder,
				use: tt.args.use,
			}

			jwks, err := BuildJWKSet([]*JWKSEntry{entry})
			if (err != nil) != tt.wantError {
				t.Fatalf("esperado erro=%v, obtido err=%v", tt.wantError, err)
			}

			if err == nil && jwks.Keys[0].Kty != tt.args.kty {
				t.Errorf("esperado tipo %s, obtido %s", tt.args.kty, jwks.Keys[0].Kty)
			}
		})
	}
}

func TestBuildJWKS_UsandoECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("erro ao gerar chave EC: %v", err)
	}

	// Serializar a chave pública em DER
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("erro ao serializar chave pública: %v", err)
	}

	// Criar um JWKSEntry com essa chave
	keyID := "arn:aws:kms:us-east-1:xxxxx:alias/passport-signer"
	holder := &KeyHolder{
		PubKey:    &kms.GetPublicKeyOutput{PublicKey: pubDER, KeyId: &keyID},
		UseFrom:   time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	entry := &JWKSEntry{
		key: holder,
		use: "sig",
	}

	cfg := &JWKSConfig{
		issuer:            "https://test.issuer",
		expireInHours:     6,
		skewTimeInSeconds: 0,
	}

	tokenStr, err := BuildJWKS([]*JWKSEntry{entry}, cfg, jwt.SigningMethodES256, priv)
	if err != nil {
		t.Fatalf("erro ao gerar token JWKS: %v", err)
	}

	// Decodificar o JWT (sem validar assinatura) e checar claims
	parser := jwt.NewParser()
	var claims struct {
		JWKS JWKS `json:"jwks"`
		jwt.RegisteredClaims
	}
	_, err = parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("erro ao parsear token: %v", err)
	}

	if len(claims.JWKS.Keys) == 0 {
		t.Fatal("JWKS vazio no token")
	}
	if claims.JWKS.Keys[0].Kid == "" || claims.JWKS.Keys[0].Alg == "" {
		t.Errorf("JWKS com campos ausentes: %+v", claims.JWKS.Keys[0])
	}
}
