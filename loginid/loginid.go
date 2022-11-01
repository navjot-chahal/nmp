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
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/navjot-chahal/nmp/fido2"
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
	PrivateKey *ecdsa.PrivateKey
	BaseURL    string

	Http *xhr.Client
}

// Creates a new Loginid client
func New(clientID string, privateKey string, baseURL string) (*LoginID, error) {
	l := &LoginID{
		ClientID: clientID,
		BaseURL:  baseURL,
		Http:     xhr.New(nil, 0),
	}
	if privateKey != "" {
		ecdsaKey, err := util.LoadPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		l.PrivateKey = ecdsaKey
	}
	return l, nil
}

// Generate a service token
func (s *LoginID) GenerateServiceToken(scope string, options *token.ServiceTokenOptions) (string, error) {
	t := token.NewServiceToken(s.ClientID, scope, options)

	jwt, err := token.SignToken(s.PrivateKey, t)
	if err != nil {
		return "", err
	}
	return jwt, err
}

// Verify a JWT token returned upon user authorization
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
 * Transaction Confirmation APIs
 */

type CreateTxOptions struct {
	Nonce string
}

// Generate an authorization token for the transaction confirmation flow
func (s *LoginID) GenerateTxAuthToken(txPayload string, options *token.TxTokenOptions) (string, error) {
	t := token.NewTxToken(s.ClientID, txPayload, options)

	jwt, err := token.SignToken(s.PrivateKey, t)
	if err != nil {
		return "", err
	}
	return jwt, nil
}

// Create a transaction and return its ID
func (s *LoginID) CreateTx(txPayload string, options *CreateTxOptions) (string, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	if s.PrivateKey != nil {
		jwt, err := s.GenerateTxAuthToken(txPayload, nil)
		if err != nil {
			return "", err
		}
		h["Authorization"] = fmt.Sprintf("Bearer %s", jwt)
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

// Verify the JWT token returned upon completion of a transaction
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

/*
 * Registration/Authentication APIs (FIDO2)
 */

// Initiate a FIDO2 registration
func (s *LoginID) RegisterFido2Init(username string, roamingAuth bool, regSession string) (*RegisterFido2InitResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	if s.PrivateKey != nil {
		jwt, err := s.GenerateServiceToken("auth.register", &token.ServiceTokenOptions{Username: username})
		if err != nil {
			return nil, err
		}
		h["Authorization"] = fmt.Sprintf("Bearer %s", jwt)
	}
	p := map[string]interface{}{
		"client_id": s.ClientID,
		"username":  username,
		"options": map[string]interface{}{
			"roaming_authentictor": roamingAuth,
			"register_session":     regSession,
		},
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/register/fido2/init", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *RegisterFido2InitResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Complete a FIDO2 registration
func (s *LoginID) RegisterFido2Complete(username string, attestationPayload fido2.AttestationPayloadRequest, credentialName string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	p := map[string]interface{}{
		"client_id":           s.ClientID,
		"username":            username,
		"attestation_payload": attestationPayload,
	}
	if credentialName != "" {
		p["options"] = map[string]string{"credential_name": credentialName}
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/register/fido2/complete", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Initialize authentication process with a FIDO2 credential
func (s *LoginID) AuthenticateFido2Init(username string) (*AuthenticateFido2InitResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	if s.PrivateKey != nil {
		jwt, err := s.GenerateServiceToken("auth.login", &token.ServiceTokenOptions{Username: username})
		if err != nil {
			return nil, err
		}
		h["Authorization"] = fmt.Sprintf("Bearer %s", jwt)
	}
	p := map[string]interface{}{
		"client_id": s.ClientID,
		"username":  username,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/authenticate/fido2/init", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticateFido2InitResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Complete authentication process with a FIDO2 credential
func (s *LoginID) AuthenticateFido2Complete(username string, assertionPayload *fido2.AssertionPayloadRequest) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	p := map[string]interface{}{
		"client_id":         s.ClientID,
		"username":          username,
		"assertion_payload": assertionPayload,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/authenticate/fido2/complete", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

/*
 * Registration/Authentication APIs (Password)
 */

// Register a new user with password
func (s *LoginID) RegisterPassword(username, password string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	p := map[string]interface{}{
		"client_id":             s.ClientID,
		"username":              username,
		"password":              password,
		"password_confirmation": password,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/register/password", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Authenticate user with password
func (s *LoginID) AuthenticatePassword(username, password string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	p := map[string]interface{}{
		"client_id": s.ClientID,
		"username":  username,
		"password":  password,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/authenticate/password", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

/*
 * Authentication APIs (Public Key)
 */

// Initialize an authentication with a public key
func (s *LoginID) AuthenticatePublicKeyInit(clientID string, username string, publickeyAlg string, publickey string) (*AuthenticatePublicKeyInitResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	if s.PrivateKey != nil {
		jwt, err := s.GenerateServiceToken("auth.login", &token.ServiceTokenOptions{Username: username})
		if err != nil {
			return nil, err
		}
		h["Authorization"] = fmt.Sprintf("Bearer %s", jwt)
	}
	p := map[string]interface{}{
		"client_id":     s.ClientID,
		"username":      username,
		"publickey_alg": publickeyAlg,
		"publickey":     publickey,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/authenticate/publickey/init", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var r *AuthenticatePublicKeyInitResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Complete an authentication with a public key
func (s *LoginID) AuthenticatePublicKeyComplete(clientID string, userID string, username string, challengeID string, assertion string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}

	keyUsernameOrUserID, valUsernameOrUserID, err := util.GetUsernameOrUserID(username, userID)
	if err != nil {
		return nil, err
	}

	p := map[string]interface{}{
		"client_id":         s.ClientID,
		"challenge_id":      challengeID,
		"assertion":         assertion,
		keyUsernameOrUserID: valUsernameOrUserID,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := s.Http.Post(fmt.Sprintf("%s/authenticate/publickey/complete", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var r *AuthenticationResponse
	if err := s.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

/*
 * Authentication APIs (Code Wait)
 */

// Authenticate via an authorized one-time code
func (s *LoginID) AuthenticateCodeWait(username string, code string, codeType string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": s.ClientID,
	}
	if s.PrivateKey != nil {
		jwt, err := s.GenerateServiceToken("auth.temporary", &token.ServiceTokenOptions{Username: username})
		if err != nil {
			return nil, err
		}
		h["Authorization"] = fmt.Sprintf("Bearer %s", jwt)
	}
	p := map[string]interface{}{
		"client_id": s.ClientID,
		"username":  username,
		"authentication_code": map[string]string{
			"code": code,
			"type": codeType,
		},
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	waitCodeHttp := xhr.New(nil, 3*time.Minute)

	res, err := waitCodeHttp.Post(fmt.Sprintf("%s/authenticate/code/wait", s.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := waitCodeHttp.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}

// Initialize adding a FIDO2 credential with pre-generated authorization code
func (m *LoginID) AddFido2CredentialWithCodeInit(userID string, username string, code string, codeType string) (*AddFido2CredentialInitResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.add", &token.ServiceTokenOptions{UserID: userID, Username: username})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}

	keyUsernameOrUserID, valUsernameOrUserID, err := util.GetUsernameOrUserID(username, userID)
	if err != nil {
		return nil, err
	}

	p := map[string]interface{}{
		"client_id": m.ClientID,
		"authentication_code": map[string]string{
			"code": code,
			"type": codeType,
		},
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/fido2/init/code", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var cred *AddFido2CredentialInitResponse
	if err := m.Http.DecodeResponse(res, &cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// Complete adding a FIDO2 credential (initialized with or without code)
func (m *LoginID) AddFido2CredentialComplete(username string, attestationPayload fido2.AttestationPayloadRequest, credentialName string) (*AuthenticationResponse, error) {
	h := map[string]string{
		"X-Client-ID": m.ClientID,
	}
	p := map[string]interface{}{
		"client_id":           m.ClientID,
		"username":            username,
		"attestation_payload": attestationPayload,
	}
	if credentialName != "" {
		p["options"] = map[string]string{"credential_name": credentialName}
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/fido2/complete", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, nil
	}

	var r *AuthenticationResponse
	if err := m.Http.DecodeResponse(res, &r); err != nil {
		return nil, err
	}
	return r, nil
}
