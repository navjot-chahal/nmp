package management

import (
	"github.com/navjot-chahal/nmp/internal/errors"
	base "github.com/navjot-chahal/nmp/loginid"
)

/*
 * This server SDK can be used with a management application and requires an API credential to be assigned to that integration.
 * All calls made from this SDK are intended to be backend-to-backend calls, as the operations are sensitive.
 */
type Management struct {
	*base.LoginID
}

// New creates a new management client
func New(clientID string, privateKey string, baseURL string) (*Management, error) {
	if privateKey == "" {
		return nil, errors.InvalidParameterErr("missing private key")
	}

	b, err := base.New(clientID, privateKey, baseURL)
	if err != nil {
		return nil, err
	}

	return &Management{LoginID: b}, err
}
