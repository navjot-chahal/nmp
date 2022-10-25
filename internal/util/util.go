package util

import "github.com/navjot-chahal/nmp/internal/errors"

func GetUsernameOrUserID(username, userID string) (string, string, error) {
	if userID != "" {
		return "user_id", userID, nil
	}

	if username != "" {
		return "username", username, nil
	}

	return "", "", errors.InvalidParameterErr("Must provide user_id or username")
}
