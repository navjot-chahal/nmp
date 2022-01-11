package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/navjot-chahal/nmp/fido2"
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

type CredentialResponse struct {
	UserID     string     `json:"user_id"`
	Credential Credential `json:"credential"`
}

type AddCredentialInitResponse struct {
	AttestationPayload fido2.AttestationPayloadResponse `json:"attestation_payload"`
}

// GetCredentials retrieves an exhaustive list of credentials for a given user
func (m *Management) GetCredentials(userID string) (*CredentialsResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.list", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	res, err := m.Http.Get(fmt.Sprintf("%s/credentials?user_id=%s", m.BaseURL, userID), h)
	if err != nil {
		return nil, err
	}

	var creds *CredentialsResponse
	if err := m.Http.DecodeResponse(res, &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

// RenameCredential updates a credential name of a user
func (m *Management) RenameCredential(userID string, credID string, updatedName string) (*CredentialResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.rename", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	p := map[string]interface{}{
		"client_id": m.ClientID,
		"user_id":   userID,
		"credential": map[string]string{
			"uuid": credID,
			"name": updatedName,
		},
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

// RevokeCredential deletes an existing user credential
func (m *Management) RevokeCredential(userID string, credID string) (*CredentialResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.revoke", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	p := map[string]interface{}{
		"client_id": m.ClientID,
		"user_id":   userID,
		"credential": map[string]string{
			"uuid": credID,
		},
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

// InitAddCredentialWithoutCode adds a credential without pre-generated authorization code
func (m *Management) InitAddCredentialWithoutCode(userID string) (*AddCredentialInitResponse, error) {
	jwt, err := m.GenerateServiceToken("credentials.force_add", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	p := map[string]interface{}{
		"client_id": m.ClientID,
		"user_id":   userID,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/credentials/fido2/init/force", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}

	var cred *AddCredentialInitResponse
	if err := m.Http.DecodeResponse(res, &cred); err != nil {
		return nil, err
	}
	return cred, nil
}
