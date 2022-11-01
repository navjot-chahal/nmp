package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/navjot-chahal/nmp/internal/util"
	"github.com/navjot-chahal/nmp/loginid"
	"github.com/navjot-chahal/nmp/token"
)

type Credential struct {
	ID        string    `json:"uuid"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type CredentialsResponse struct {
	UserID      string       `json:"user_id"`
	Credentials []Credential `json:"credentials"`
}

// Retrieves an exhaustive list of credentials for a given user_id or username
func (m *Management) GetCredentials(userID string, username string) (*CredentialsResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.list", &token.ServiceTokenOptions{UserID: userID})
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
		"client_id":         m.ClientID,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/list", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var creds *CredentialsResponse
	if err := m.Http.DecodeResponse(res, &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

type CredentialResponse struct {
	UserID     string     `json:"user_id"`
	Credential Credential `json:"credential"`
}

// Renames a user credential
func (m *Management) RenameCredential(userID string, username string, credID string, updatedName string) (*CredentialResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.rename", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"credential": map[string]string{
			"uuid": credID,
			"name": updatedName,
		},
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/rename", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var cred *CredentialResponse
	if err := m.Http.DecodeResponse(res, &cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// Revokes an existing user credential
func (m *Management) RevokeCredential(userID string, username string, credID string) (*CredentialResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.revoke", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"credential": map[string]string{
			"uuid": credID,
		},
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/revoke", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var cred *CredentialResponse
	if err := m.Http.DecodeResponse(res, &cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// Initialize adding a FIDO2 credential without pre-generated authorization code
func (m *Management) ForceAddFido2CredentialInit(userID string, username string, displayName string, roamingAuthenticator bool) (*loginid.AddFido2CredentialInitResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.force_add", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"client_id":         m.ClientID,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	o := map[string]interface{}{
		"roaming_authenticator": roamingAuthenticator,
	}
	if displayName != "" {
		o["display_name"] = displayName
	}
	p["options"] = o

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/fido2/init/force", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var cred *loginid.AddFido2CredentialInitResponse
	if err := m.Http.DecodeResponse(res, &cred); err != nil {
		return nil, err
	}
	return cred, nil
}

type GenerateRecoveryCodeResponse struct {
	Code      string `json:"code"`
	CreatedAt string `json:"created_at"`
}

// Generates a recovery code
func (m *Management) GenerateRecoveryCode(clientID string, userID string, username string) (*GenerateRecoveryCodeResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.add_recovery", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"client_id":         m.ClientID,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/recovery-code", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var code *GenerateRecoveryCodeResponse
	if err := m.Http.DecodeResponse(res, &code); err != nil {
		return nil, err
	}
	return code, nil
}

type AddPublicKeyCredentialResponse struct {
	Code      string `json:"code"`
	CreatedAt string `json:"created_at"`
}

// Add a public key as a new credential
func (m *Management) AddPublicKeyCredential(clientID string, userID string, username string, publickeyAlg string, publickey string, credentialName string) (*loginid.AuthenticationResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.force_add", &token.ServiceTokenOptions{UserID: userID, Username: username})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
	}

	keyUsernameOrUserID, valUsernameOrUserID, err := util.GetUsernameOrUserID(username, userID)
	if err != nil {
		return nil, err
	}

	p := map[string]interface{}{
		"client_id":         m.ClientID,
		"publickey_alg":     publickeyAlg,
		"publickey":         publickey,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	if credentialName != "" {
		p["options"] = map[string]string{"credential_name": credentialName}
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/publickey", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var ar *loginid.AuthenticationResponse
	if err := m.Http.DecodeResponse(res, &ar); err != nil {
		return nil, err
	}
	return ar, nil
}
