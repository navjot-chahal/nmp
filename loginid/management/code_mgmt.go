package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/navjot-chahal/nmp/internal/util"
	"github.com/navjot-chahal/nmp/token"
)

type CodePurpose string

const (
	TempAuth      CodePurpose = "temporary_authentication"
	AddCredential CodePurpose = "add_credential"
)

type GenerateCodeResponse struct {
	Code         string    `json:"code"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsAuthorized bool      `json:"is_authorized"`
}

// GenerateCode generates a new code
func (m *Management) GenerateCode(userID string, username string, codeType string, purpose CodePurpose, isAuthorized bool) (*GenerateCodeResponse, error) {
	jwt, err := m.GenerateServiceToken("codes.generate", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"purpose":           purpose,
		"authorize":         isAuthorized,
		keyUsernameOrUserID: valUsernameOrUserID,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/codes/%s/generate", m.BaseURL, codeType), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var gc *GenerateCodeResponse
	if err := m.Http.DecodeResponse(res, &gc); err != nil {
		return nil, err
	}
	return gc, nil
}

type AuthorizeCodeResponse struct {
	ExpiresAt    time.Time `json:"expires_at"`
	IsAuthorized bool      `json:"is_authorized"`
}

// AuthorizeCode authorizes the given code
func (m *Management) AuthorizeCode(userID string, username string, codeType string, purpose CodePurpose, code string) (*AuthorizeCodeResponse, error) {
	jwt, err := m.GenerateServiceToken("codes.authorize", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"purpose":           purpose,
		"code":              code,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/codes/%s/authorize", m.BaseURL, codeType), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var ac *AuthorizeCodeResponse
	if err := m.Http.DecodeResponse(res, &ac); err != nil {
		return nil, err
	}
	return ac, nil
}

type InvalidateCodeResponse struct {
	DeletedAt time.Time `json:"deleted_at"`
}

// InvalidateAllCodes invalidates the codes
func (m *Management) InvalidateAllCodes(userID string, username string, codeType string, purpose CodePurpose) (*InvalidateCodeResponse, error) {
	jwt, err := m.GenerateServiceToken("codes.invalidate", &token.ServiceTokenOptions{UserID: userID, Username: username})
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
		"purpose":           purpose,
		keyUsernameOrUserID: valUsernameOrUserID,
	}

	d, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	res, err := m.Http.Post(fmt.Sprintf("%s/codes/%s/invalidate-all", m.BaseURL, codeType), bytes.NewBuffer(d), h)
	if err != nil {
		return nil, err
	}
	var ic *InvalidateCodeResponse
	if err := m.Http.DecodeResponse(res, &ic); err != nil {
		return nil, err
	}
	return ic, nil
}
