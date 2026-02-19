package jwt

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenIssuer struct {
	PrivateKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
	TokenDuration time.Duration
}

func NewTokenIssuer() (*TokenIssuer, error) {
	defaultDuration := os.Getenv("TOKEN_LIFETIME")
	if defaultDuration == "" {
		defaultDuration = "4h"
	}
	privateKeyPath := os.Getenv("PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		privateKeyPath = ECDSAPrivateKey
	}
	publicKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if publicKeyPath == "" {
		publicKeyPath = ECDSAPublicKey
	}

	duration, err := time.ParseDuration(defaultDuration)
	if err != nil {
		return nil, fmt.Errorf("unable to parse duration %s", defaultDuration)
	}

	if _, errStat := os.Stat(privateKeyPath); os.IsNotExist(errStat) {
		return nil, errStat
	}

	if _, errStat := os.Stat(publicKeyPath); os.IsNotExist(errStat) {
		return nil, errStat
	}

	privatePEM, errPrivateKey := os.ReadFile(privateKeyPath)
	if errPrivateKey != nil {
		return nil, fmt.Errorf("unable to read ECDSA private key %w", errPrivateKey)
	}
	publicPEM, errPublicKey := os.ReadFile(publicKeyPath)
	if errPublicKey != nil {
		return nil, fmt.Errorf("unable to read ECDSA public key %w", errPublicKey)
	}

	var ecdsaPrivateKey *ecdsa.PrivateKey
	var ecdsaPublicKey *ecdsa.PublicKey
	if ecdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(privatePEM); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPublicKey, err = jwt.ParseECPublicKeyFromPEM(publicPEM); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA public key: %v", err)
	}

	return &TokenIssuer{
		PrivateKey:    ecdsaPrivateKey,
		PublicKey:     ecdsaPublicKey,
		TokenDuration: duration,
	}, nil
}
