package management

import (
	base "github.com/navjot-chahal/nmp/loginid"
)

/*
 * This server SDK can be used with a management application and requires an API credential to be assigned to that integration.
 * All calls made from this SDK are intended to be backend-to-backend calls, as the operations are sensitive.
 */
type Management struct {
	*base.LoginID
}

// New creates a new Management client
func New(clientID string, privateKey string, baseURL string) (*Management, error) {
	b, err := base.New(clientID, privateKey, baseURL)
	if err != nil {
		return nil, err
	}

	return &Management{LoginID: b}, err
}
