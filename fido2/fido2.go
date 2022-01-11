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

type AttestationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int32  `json:"alg"`
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
