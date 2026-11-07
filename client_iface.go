package kyc

import (
	"context"
	"net/http"
)

// Provider runs KYC verification flows (mock-friendly client surface).
type Provider interface {
	// Start creates a verification session and returns a redirect URL.
	Start(ctx context.Context, req StartRequest) (StartResult, error)
	// Status fetches the current verification state by external ID.
	Status(ctx context.Context, externalID string) (StatusResult, error)
	// VerifyWebhook validates and parses an inbound webhook request.
	VerifyWebhook(ctx context.Context, headers http.Header, body []byte) (WebhookEvent, error)
}

// HTTPDoer performs HTTP requests; *http.Client implements this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
