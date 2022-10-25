package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/navjot-chahal/nmp/internal/util"
)

type ServiceTokenOptions struct {
	Username string
	UserID   string
	Nonce    string
}
type serviceTokenPayload struct {
	ClientID string `json:"client_id"`
	Type     string `json:"type"`
	Nonce    string `json:"nonce"`
	Iat      int64  `json:"iat"`
	Username string `json:"udata,omitempty"`
	UserID   string `json:"user_id,omitempty"`
}

type ServiceToken struct {
	Header  Header
	Payload serviceTokenPayload
}

func (t *ServiceToken) GetHeader() interface{} {
	return t.Header
}

func (t *ServiceToken) GetPayload() interface{} {
	return t.Payload
}

// NewServiceToken creates a new LoginID service token
func NewServiceToken(clientID string, scope string, opts *ServiceTokenOptions) *ServiceToken {
	h := Header{
		Typ: "JWT",
		Alg: "ES256",
	}

	p := serviceTokenPayload{
		ClientID: clientID,
		Type:     scope,
		Nonce:    util.GenerateRandomString(16),
		Iat:      time.Now().Unix(),
	}

	if opts != nil {
		if opts.Nonce != "" {
			p.Nonce = opts.Nonce
		}
		if opts.UserID != "" {
			p.UserID = opts.UserID
		}
		if opts.Username != "" {
			p.Username = opts.Username
		}
	}

	return &ServiceToken{
		Header:  h,
		Payload: p,
	}
}

// DecodeServiceTokenPayload decodes the service token payload
func DecodeServiceTokenPayload(token string) (*ServiceToken, error) {
	var err error
	decodePayload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.New("unable to decode service token payload")
	}

	var p serviceTokenPayload
	if err := json.Unmarshal(decodePayload, &p); err != nil {
		return nil, errors.New("unable to parse service token payload")
	}
	return &ServiceToken{Payload: p}, nil
}
