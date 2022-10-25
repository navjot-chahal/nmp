package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/navjot-chahal/nmp/token"
)

type UserResponse struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Status      string    `json:"status"`
	NamespaceID string    `json:"namespace_id"`
	ClientID    string    `json:"client_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Add a new user without credentials. The new user can create new credentials with recovery flow
func (m *Management) AddUserWithoutCred(username string) (*UserResponse, error) {
	jwt, err := m.GenerateServiceToken("users.create", &token.ServiceTokenOptions{Username: username})
	if err != nil {
		return nil, err
	}

	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}

	p := map[string]string{
		"username": username,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/manage/users", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var u *UserResponse
	if err := m.Http.DecodeResponse(res, &u); err != nil {
		return nil, err
	}
	return u, nil
}

// Retrieves a user account by username
func (m *Management) GetUserByUsername(username string) (*UserResponse, error) {
	jwt, err := m.GenerateServiceToken("users.retrieve", &token.ServiceTokenOptions{Username: username})
	if err != nil {
		return nil, err
	}

	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}

	p := map[string]string{
		"username": username,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/manage/users/retrieve", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var u *UserResponse
	if err := m.Http.DecodeResponse(res, &u); err != nil {
		return nil, err
	}
	return u, nil
}

// Deletes a user account by username
func (m *Management) DeleteUserByUsername(username string) error {
	jwt, err := m.GenerateServiceToken("users.delete", &token.ServiceTokenOptions{Username: username})
	if err != nil {
		return err
	}

	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}

	p := map[string]string{
		"username": username,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/manage/users/delete", m.BaseURL), bytes.NewBuffer(d), h)
	if err != nil {
		return err
	}
	if err := m.Http.DecodeResponse(res, nil); err != nil {
		return err
	}
	return nil
}

// Deletes a user account by user id
func (m *Management) DeleteUserById(userID string) error {
	jwt, err := m.GenerateServiceToken("users.delete", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	res, err := m.Http.Delete(fmt.Sprintf("%s/manage/users/%s", m.BaseURL, userID), h)
	if err != nil {
		return err
	}
	if err := m.Http.DecodeResponse(res, nil); err != nil {
		return err
	}
	return nil
}

// Activates a user account by user id
func (m *Management) ActivateUserById(userID string) (*UserResponse, error) {
	jwt, err := m.GenerateServiceToken("users.activate", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	res, err := m.Http.Put(fmt.Sprintf("%s/manage/users/%s/activate", m.BaseURL, userID), nil, h)
	if err != nil {
		return nil, err
	}
	var u *UserResponse
	if err := m.Http.DecodeResponse(res, &u); err != nil {
		return nil, err
	}
	return u, nil
}

// Deactivates a user account by user id
func (m *Management) DeactivateUserById(userID string) (*UserResponse, error) {
	jwt, err := m.GenerateServiceToken("users.deactivate", &token.ServiceTokenOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", jwt),
		"X-Client-ID":   m.ClientID,
	}
	res, err := m.Http.Put(fmt.Sprintf("%s/manage/users/%s/deactivate", m.BaseURL, userID), nil, h)
	if err != nil {
		return nil, err
	}
	var u *UserResponse
	if err := m.Http.DecodeResponse(res, &u); err != nil {
		return nil, err
	}
	return u, nil
}
