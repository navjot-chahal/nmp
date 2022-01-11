package errors

import (
	"encoding/json"
	"fmt"
	"io"
)

type Error interface {
	// ErrorCode returns LoginID error code returned by the server
	ErrorCode() string
	ErrorDescription() string
	error
}

type LoginidError struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Err         error  `json:"error"`
}

func (e *LoginidError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (e *LoginidError) ErrorCode() string {
	return e.Code
}

func (e *LoginidError) ErrorDescription() string {
	return e.Description
}

func (e *LoginidError) Unwrap() error {
	return e.Err
}

func NewLoginidError(code string, err error, message string, params ...interface{}) *LoginidError {
	return &LoginidError{
		Code:        code,
		Description: fmt.Sprintf(message, params...),
		Err:         err,
	}
}

func LoginidErrorFromReader(r io.Reader) error {
	e := &struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.NewDecoder(r).Decode(e)
	if err != nil {
		return err
	}
	return NewLoginidError(e.Code, nil, e.Message)
}
