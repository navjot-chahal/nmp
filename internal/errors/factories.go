package errors

func InvalidTokenErr(err error, message string, params ...interface{}) Error {
	return NewLoginidError(InvalidToken, err, message, params...)
}

func InvalidPublicKeyErr(err error, message string, params ...interface{}) Error {
	return NewLoginidError(InvalidPublicKey, err, message, params...)
}

func UnsupportedAlgErr(message string, params ...interface{}) Error {
	return NewLoginidError(UnsupportedAlg, nil, message, params...)
}
