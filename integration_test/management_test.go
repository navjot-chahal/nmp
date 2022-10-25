package integrationtest

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/navjot-chahal/nmp/loginid/management"
	"github.com/stretchr/testify/suite"
)

type e2eTestSuite struct {
	suite.Suite
	lm *management.Management
}

func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, &e2eTestSuite{})
}

func (s *e2eTestSuite) SetupSuite() {
	var err error
	baseURL := getEnv("BASE_URL", "https://directweb.usw1.loginid.io")
	clientID := getEnv("MANAGEMENT_CLIENT_ID", "")
	privateKey := getEnv("PRIVATE_KEY", "")

	s.lm, err = management.New(clientID, privateKey, baseURL)
	if err != nil {
		fmt.Errorf("Failed to create Management instance: %s", err.Error())
	}
}

func (s *e2eTestSuite) TestUserManagement() {
	username := uuid.New().String() + "@loginid.io"

	user, err := s.lm.AddUserWithoutCred(username)
	s.NoError(err)
	s.Equal(username, user.Username)
	s.Equal("active", user.Status)
	s.Equal(s.lm.ClientID, user.ClientID)

	u, err := s.lm.GetUserByUsername(username)
	s.NoError(err)
	s.Equal(username, u.Username)
	s.Equal("active", u.Status)
	s.Equal(s.lm.ClientID, u.ClientID)

	ua, err := s.lm.DeactivateUserById(u.ID)
	s.NoError(err)
	s.Equal(u.ID, ua.ID)
	s.Equal(username, ua.Username)
	s.Equal("inactive", ua.Status)
	s.Equal(s.lm.ClientID, ua.ClientID)

	ua, err = s.lm.ActivateUserById(u.ID)
	s.NoError(err)
	s.Equal(u.ID, ua.ID)
	s.Equal(username, ua.Username)
	s.Equal("active", ua.Status)
	s.Equal(s.lm.ClientID, ua.ClientID)

	err = s.lm.DeleteUserById(u.ID)
	s.NoError(err)

	_, err = s.lm.GetUserByUsername(username)
	s.Error(err)
}

func (s *e2eTestSuite) TestDeleteUserByUsername() {
	username := uuid.New().String() + "@loginid.io"

	user, err := s.lm.AddUserWithoutCred(username)
	s.NoError(err)
	s.Equal(username, user.Username)
	s.Equal("active", user.Status)
	s.Equal(s.lm.ClientID, user.ClientID)

	err = s.lm.DeleteUserByUsername(user.Username)
	s.NoError(err)

	_, err = s.lm.GetUserByUsername(username)
	s.Error(err)
}

func (s *e2eTestSuite) TestCodeManagement() {
	username := uuid.New().String() + "@loginid.io"

	user, err := s.lm.AddUserWithoutCred(username)
	s.NoError(err)

	gc, err := s.lm.GenerateCode("", user.Username, "short", "temporary_authentication", true)
	s.NoError(err)
	s.Equal(true, gc.IsAuthorized)
	s.NotEmpty(gc.Code)
	s.NotEmpty(gc.ExpiresAt)

	ac, err := s.lm.AuthorizeCode(user.ID, "", "short", "temporary_authentication", gc.Code)
	s.NoError(err)
	s.Equal(true, ac.IsAuthorized)
	s.NotEmpty(ac.ExpiresAt)

	ic, err := s.lm.InvalidateAllCodes("", user.Username, "short", "temporary_authentication")
	s.NoError(err)
	s.NotEmpty(ic.DeletedAt)

	err = s.lm.DeleteUserById(user.ID)
	s.NoError(err)
}

// [Not completed]
// Requires a user with a valid credential
//
// func (s *e2eTestSuite) TestCredManagement() {
//     creds, err := s.lm.GetCredentials(user.ID)
// 	s.NoError(err)

// 	cred, err := s.lm.RenameCredential(user.ID, creds[0].ID, "TestCredGO")
// 	s.NoError(err)

// 	credInit, err := s.lm.InitAddCredentialWithoutCode(user.ID)
// 	s.NoError(err)

// 	c, err := s.lm.RevokeCredential(user.ID, cred.ID)
// 	s.NoError(err)
// }

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
