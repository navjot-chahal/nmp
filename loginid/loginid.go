package loginid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/navjot-chahal/nmp/internal/errors"
	"github.com/navjot-chahal/nmp/internal/util"
	"github.com/navjot-chahal/nmp/internal/xhr"
	"github.com/navjot-chahal/nmp/token"
)

/*
* This server SDK leverages either a web or mobile application
* and requires an API credential to be assigned to that integration.
 */
type LoginID struct {
	ClientID   string
	PrivateKey string
	BaseURL    string

	Http *xhr.Client
}

// New creates a new Loginid client
func New(clientID string, privateKey string, baseURL string) (*LoginID, error) {
	l := &LoginID{
		ClientID:   clientID,
		PrivateKey: privateKey,
		BaseURL:    baseURL,
		Http:       xhr.New(nil),
	}
	return l, nil
}

// GenerateServiceToken generate a service token
func (s *LoginID) GenerateServiceToken(scope string, options *token.ServiceTokenOptions) (string, error) {
	t := token.NewServiceToken(s.ClientID, scope, options)

	jwt, err := token.SignToken(s.PrivateKey, t)
	if err != nil {
		return "", err
	}
	return jwt, err
}

// VerifyToken verifies a JWT token returned upon user authorization
func (s *LoginID) VerifyToken(tokenString string, username *string) (bool, error) {
	var err error
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false, errors.InvalidTokenErr(nil, "invalid JWT structure")
	}
	h, err := token.DecodeTokenHeader(parts[0])
	if err != nil {
		return false, errors.InvalidTokenErr(err, "invalid JWT header")
	}

	if h.Alg != "ES256" {
		return false, errors.UnsupportedAlgErr("%s is not a supported algorithm", h.Alg)
	}

	publicKey, err := s.GetPublicKey(h.Kid)
	if err != nil {
		return false, errors.InvalidPublicKeyErr(err, "unable to retrieve ECDSA public key")
	}

	var ecdsaKey *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPublicKeyFromPEM([]byte(publicKey)); err != nil {
		return false, errors.InvalidPublicKeyErr(err, "unable to parse ECDSA public key")
	}

	method := jwt.GetSigningMethod(h.Alg)
	err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ecdsaKey)
	if err != nil {
		return false, errors.InvalidTokenErr(err, "unable to verify JWT signature")
	}

	p, err := token.DecodeServiceTokenPayload(parts[1])
	if err != nil {
		return false, errors.InvalidTokenErr(err, "invalid JWT payload")
	}

	if username != nil && *username != "" {
		return p.Payload.Username == *username, nil
	}
	return true, nil
}

// GetPublicKey extracts the client's public key with `kid`
func (s *LoginID) GetPublicKey(kid string) (string, error) {
	res, err := s.Http.Get(fmt.Sprintf("%s/certs?kid=%s", s.BaseURL, kid), nil)
	if err != nil {
		return "", err
	}

	if res.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		pk := string(bodyBytes)
		return pk, nil
	} else {
		return "", errors.LoginidErrorFromReader(res.Body)
	}
}

/*
 * Transaction Confirmation related functions
 */

type CreateTxOptions struct {
	Nonce string
}

// GenerateTxAuthToken generate an Authorization Token for Transaction Flow
func (s *LoginID) GenerateTxAuthToken(txPayload string, options *token.TxTokenOptions) (string, error) {
	t := token.NewTxToken(s.ClientID, txPayload, options)

	jwt, err := token.SignToken(s.PrivateKey, t)
	if err != nil {
		return "", err
	}
	return jwt, nil
}

// CreateTx create a Transaction ID
func (s *LoginID) CreateTx(txPayload string, options *CreateTxOptions) (string, error) {
	jwt, err := s.GenerateTxAuthToken(txPayload, nil)
	if err != nil {
		return "", err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   s.ClientID,
	}

	p := map[string]interface{}{
		"client_id":  s.ClientID,
		"tx_payload": txPayload,
		"nonce":      util.GenerateRandomString(16),
	}

	if options != nil {
		if options.Nonce != "" {
			p["nonce"] = options.Nonce
		}
	}

	d, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	res, err := s.Http.Post(fmt.Sprintf("%s/tx", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return "", nil
	}

	tx := struct {
		ID string `json:"id"`
	}{}
	if err := s.Http.DecodeResponse(res, &tx); err != nil {
		return "", err
	}
	return tx.ID, nil
}

// VerifyTransaction verify the jwt token returned upon completion of a transaction
func (s *LoginID) VerifyTransaction(tokenString string, txPayload string) (bool, error) {
	var err error
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false, errors.InvalidTokenErr(nil, "invalid JWT structure")
	}
	h, err := token.DecodeTokenHeader(parts[0])
	if err != nil {
		return false, errors.InvalidTokenErr(err, "invalid JWT header")
	}

	if h.Alg != "ES256" {
		return false, errors.UnsupportedAlgErr("%s is not a supported algorithm", h.Alg)
	}

	publicKey, err := s.GetPublicKey(h.Kid)
	if err != nil {
		return false, errors.InvalidPublicKeyErr(err, "unable to retrieve ECDSA public key")
	}

	var ecdsaKey *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPublicKeyFromPEM([]byte(publicKey)); err != nil {
		return false, errors.InvalidPublicKeyErr(err, "unable to parse ECDSA public key")
	}

	method := jwt.GetSigningMethod(h.Alg)
	err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ecdsaKey)
	if err != nil {
		return false, errors.InvalidTokenErr(err, "unable to verify JWT signature")
	}

	p, err := token.DecodeTxTokenPayload(parts[1])
	if err != nil {
		return false, errors.InvalidTokenErr(err, "invalid JWT payload")
	}

	//hash and encode txPayload
	toHash := txPayload + p.Payload.Nonce + p.Payload.ServerNonce
	hash := sha256.Sum256([]byte(toHash))
	ph := base64.RawURLEncoding.EncodeToString(hash[:])

	return ph == p.Payload.TxHash, nil
}
