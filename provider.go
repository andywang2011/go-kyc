package kyc

import (
	"errors"
	"strings"
)

// Status is the verification outcome for a KYC session.
type Status string

const (
	// StatusPending means verification is in progress.
	StatusPending Status = "pending"
	// StatusApproved means the subject passed verification.
	StatusApproved Status = "approved"
	// StatusRejected means verification failed or was declined.
	StatusRejected Status = "rejected"
)

// StartRequest begins a verification flow for a subject.
type StartRequest struct {
	// SubjectID is the caller's stable user or account identifier.
	SubjectID string
	// ReturnURL is where the user is redirected after completing the flow.
	ReturnURL string
	// Locale is a BCP 47 language tag for the provider UI (optional).
	Locale string
}

// StartResult holds provider-side identifiers after starting verification.
type StartResult struct {
	// ExternalID is the provider verification session or inquiry ID.
	ExternalID string
	// RedirectURL is the URL to open in a browser or webview.
	RedirectURL string
}

// StatusResult is the current state of a verification session.
type StatusResult struct {
	// ExternalID matches the ID returned from Start.
	ExternalID string
	// Status is pending, approved, or rejected.
	Status Status
}

// WebhookEvent is a normalized event parsed from a provider webhook.
type WebhookEvent struct {
	// ExternalID is the provider verification session ID.
	ExternalID string
	// Status is the new verification status when known.
	Status Status
	// EventType is the raw provider event name when available.
	EventType string
}

func validateStartRequest(req StartRequest) error {
	if strings.TrimSpace(req.SubjectID) == "" {
		return errors.New("kyc subject id is not set")
	}
	if strings.TrimSpace(req.ReturnURL) == "" {
		return errors.New("kyc return url is not set")
	}
	return nil
}

func validateExternalID(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("kyc external id is not set")
	}
	return nil
}

func parseStatus(s string) (Status, error) {
	switch Status(strings.ToLower(strings.TrimSpace(s))) {
	case StatusPending, StatusApproved, StatusRejected:
		return Status(strings.ToLower(strings.TrimSpace(s))), nil
	default:
		return "", errors.New("kyc unknown status: " + s)
	}
}
