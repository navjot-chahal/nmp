package util

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
)

func LoadPublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	// decode the key, assuming it's in PEM format
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode pem public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse ecdsa public key")
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, errors.New("unsupported public key type")
}

func LoadPrivateKey(privateKey string) (*ecdsa.PrivateKey, error) {
	// decode the key, assuming it's in PEM format
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("failed to decode pem private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse ecdsa private key")
	}
	return privKey, nil
}

func GenerateRandomString(n int) string {
	var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

	numLetters := big.NewInt(int64(len(letters)))
	s := make([]rune, n)
	for i := range s {
		idx, err := rand.Int(rand.Reader, numLetters)
		if err != nil {
			panic(err)
		}
		s[i] = letters[idx.Int64()]
	}
	return string(s)
}
