package fido2

type AttestationPayloadResponse struct {
	CredentialUUID         string                 `json:"credential_uuid,omitempty"`
	Challenge              string                 `json:"challenge"`
	Rp                     map[string]string      `json:"rp"`
	User                   AttestationUser        `json:"user"`
	PubKeyCredParams       []PubKeyCredParam      `json:"pubKeyCredParams"`
	ExcludeCredentials     []ExcludeCredential    `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation,omitempty"`
	Timeout                int                    `json:"timeout,omitempty"`
}

type AttestationPayloadRequest struct {
	CredentialUUID  string `json:"credential_uuid"`
	CredentialID    string `json:"credential_id"`
	Challenge       string `json:"challenge"`
	ClientData      string `json:"client_data"`
	AttestationData string `json:"attestation_data"`
}

type AttestationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type AssertionPayloadResponse struct {
	Challenge        string            `json:"challenge"`
	RpID             string            `json:"rpId"`
	AllowCredentials []AllowCredential `json:"allowCredentials"`
	Timeout          int               `json:"timeout,omitempty"`
	UserVerification string            `json:"userVerification"`
}

type AssertionPayloadRequest struct {
	CredentialID      string `json:"credential_id"`
	Challenge         string `json:"challenge"`
	ClientData        string `json:"client_data"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         int    `json:"signature"`
}

type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int32  `json:"alg"`
}

type AllowCredential struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports"`
	Type       string   `json:"type"`
}

type ExcludeCredential struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports"`
	Type       string   `json:"type"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	UserVerification        string `json:"userVerification"`
}
