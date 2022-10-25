package loginid

import "github.com/navjot-chahal/nmp/fido2"

type AuthenticationClient struct {
	ClientId   string `json:"id"`
	ClientType string `json:"type"`
}

type AuthenticationCred struct {
	Uuid           string `json:"id"`
	CredentialType string `json:"type"`
	Name           string `json:"name"`
}

type AuthenticationUser struct {
	UserId      string `json:"id"`
	Username    string `json:"username"`
	NamespaceID string `json:"namespace_id"`
}

type AuthenticationResponse struct {
	Client          AuthenticationClient `json:"client"`
	Credential      AuthenticationCred   `json:"credential"`
	User            AuthenticationUser   `json:"user"`
	Jwt             string               `json:"jwt"`
	IsAuthenticated bool                 `json:"is_authenticated"`
}

type RegisterFido2InitResponse struct {
	AttestationPayload fido2.AttestationPayloadResponse `json:"attestation_payload"`
	RegisterSession    string                           `json:"register_session,omitempty"`
}

type AuthenticateFido2InitResponse struct {
	AssertionPayload fido2.AssertionPayloadResponse `json:"assertion_payload"`
}

type AuthenticateDocScanInitResponse struct {
	CredentialUUID string `json:"credential_uuid"`
	IFrameURL      string `json:"iframe_url"`
}

type AuthenticatePublicKeyInitResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"server_nonce"`
}

type AddFido2CredentialInitResponse struct {
	AttestationPayload fido2.AttestationPayloadResponse `json:"attestation_payload"`
}
