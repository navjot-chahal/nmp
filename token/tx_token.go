package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/navjot-chahal/nmp/internal/util"
)

type TxTokenOptions struct {
	Nonce string
}
type txTokenPayload struct {
	ClientID    string `json:"client_id"`
	Type        string `json:"type"`
	Nonce       string `json:"nonce"`
	Iat         int64  `json:"iat"`
	PayloadHash string `json:"payload_hash"`
	ServerNonce string `json:"server_nonce,omitempty"`
	TxHash      string `json:"tx_hash,omitempty"`
}

type TxToken struct {
	Header  Header
	Payload txTokenPayload
}

func (t *TxToken) GetHeader() interface{} {
	return t.Header
}

func (t *TxToken) GetPayload() interface{} {
	return t.Payload
}

// NewTxToken creates a new LoginID transaction token
func NewTxToken(clientID string, txPayload string, opts *TxTokenOptions) *TxToken {
	h := Header{
		Typ: "JWT",
		Alg: "ES256",
	}

	//hash and encode txPayload
	hash := sha256.Sum256([]byte(txPayload))
	ph := base64.RawURLEncoding.EncodeToString(hash[:])

	p := txTokenPayload{
		ClientID:    clientID,
		Type:        "tx.create",
		Nonce:       util.GenerateRandomString(16),
		Iat:         time.Now().Unix(),
		PayloadHash: ph,
	}

	if opts != nil {
		if opts.Nonce != "" {
			p.Nonce = opts.Nonce
		}
	}

	return &TxToken{
		Header:  h,
		Payload: p,
	}
}

// DecodeTxTokenPayload decodes the transaction token payload
func DecodeTxTokenPayload(token string) (*TxToken, error) {
	var err error
	decodePayload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.New("unable to decode tx token payload")
	}

	var p txTokenPayload
	if err := json.Unmarshal(decodePayload, &p); err != nil {
		return nil, errors.New("unable to parse tx token payload")
	}
	return &TxToken{Payload: p}, nil
}
