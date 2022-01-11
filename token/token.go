package token

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/navjot-chahal/nmp/internal/util"
)

type Token interface {
	GetHeader() interface{}
	GetPayload() interface{}
}

type Header struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// DecodeTokenHeader decodes JWT header
func DecodeTokenHeader(tokenHeader string) (*Header, error) {
	var err error

	var decodedHeader []byte
	if decodedHeader, err = base64.RawURLEncoding.DecodeString(tokenHeader); err != nil {
		return nil, errors.New("unable to decode token header")
	}

	h := &Header{}
	if err := json.Unmarshal(decodedHeader, h); err != nil {
		return nil, errors.New("unable to parse token header")
	}
	return h, nil
}

func SignToken(privateKey string, tok Token) (string, error) {
	var err error
	method := jwt.GetSigningMethod("ES256")

	var ecdsaKey *ecdsa.PrivateKey
	if ecdsaKey, err = util.LoadPrivateKey(privateKey); err != nil {
		return "", err
	}

	header := tok.GetHeader()
	var jsonValue []byte
	if jsonValue, err = json.Marshal(header); err != nil {
		return "", errors.New("unable to sign key")
	}
	headerEncode := jwt.EncodeSegment(jsonValue)

	p := tok.GetPayload()
	if jsonValue, err = json.Marshal(p); err != nil {
		return "", errors.New("unable to sign key")
	}
	payloadEncode := jwt.EncodeSegment(jsonValue)

	// sign the joining of headerEncode & payload
	var sig string
	if sig, err = method.Sign(strings.Join([]string{headerEncode, payloadEncode}, "."), ecdsaKey); err != nil {
		return "", err
	}
	return strings.Join([]string{headerEncode, payloadEncode, sig}, "."), nil
}
