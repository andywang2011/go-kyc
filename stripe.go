package kyc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type stripeIdentityProvider struct {
	secretKey        string
	webhookSecret    string
	webhookTolerance time.Duration
	baseURL          string
	client           HTTPDoer
	now              func() time.Time
}

// NewStripeIdentity creates a Stripe Identity verification provider stub.
func NewStripeIdentity(cfg StripeIdentityConfig) (Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	return &stripeIdentityProvider{
		secretKey:        cfg.SecretKey,
		webhookSecret:    cfg.WebhookSecret,
		webhookTolerance: cfg.WebhookTolerance,
		baseURL:          cfg.resolvedBaseURL(),
		client:           client,
		now:              time.Now,
	}, nil
}

// Start creates a verification session.
func (p *stripeIdentityProvider) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if err := validateStartRequest(req); err != nil {
		return StartResult{}, err
	}

	form := url.Values{}
	form.Set("type", "document")
	form.Set("return_url", req.ReturnURL)
	form.Set("metadata[subject_id]", req.SubjectID)
	if req.Locale != "" {
		form.Set("options[document][allowed_types][]", "driving_license")
		form.Set("metadata[locale]", req.Locale)
	}

	reqURL := p.baseURL + stripeCreateSessionPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return StartResult{}, fmt.Errorf("stripe create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.secretKey)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StartResult{}, fmt.Errorf("stripe request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StartResult{}, fmt.Errorf("stripe api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ID     string `json:"id"`
		URL    string `json:"url"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StartResult{}, fmt.Errorf("stripe decode response: %w", err)
	}
	if parsed.ID == "" {
		return StartResult{}, fmt.Errorf("stripe missing session id")
	}
	return StartResult{ExternalID: parsed.ID, RedirectURL: parsed.URL}, nil
}

// Status retrieves a verification session by ID.
func (p *stripeIdentityProvider) Status(ctx context.Context, externalID string) (StatusResult, error) {
	if err := validateExternalID(externalID); err != nil {
		return StatusResult{}, err
	}

	reqURL := p.baseURL + stripeCreateSessionPath + "/" + url.PathEscape(externalID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return StatusResult{}, fmt.Errorf("stripe create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.secretKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StatusResult{}, fmt.Errorf("stripe request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StatusResult{}, fmt.Errorf("stripe api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StatusResult{}, fmt.Errorf("stripe decode response: %w", err)
	}
	st, err := mapStripeStatus(parsed.Status)
	if err != nil {
		return StatusResult{}, err
	}
	return StatusResult{ExternalID: parsed.ID, Status: st}, nil
}

// VerifyWebhook verifies the Stripe-Signature header (t=<unix>,v1=<hex>) using
// HMAC-SHA256 over "<timestamp>.<payload>" with the webhook secret, enforces the
// timestamp tolerance, and then parses the identity verification session event.
// It returns ErrWebhookUnverifiable when no webhook secret is configured.
func (p *stripeIdentityProvider) VerifyWebhook(_ context.Context, headers http.Header, body []byte) (WebhookEvent, error) {
	if err := verifyTimestampedHMAC(p.webhookSecret, headers.Get("Stripe-Signature"), body, p.webhookTolerance, p.now()); err != nil {
		return WebhookEvent{}, fmt.Errorf("stripe webhook: %w", err)
	}

	var envelope struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return WebhookEvent{}, fmt.Errorf("stripe webhook decode: %w", err)
	}
	obj := envelope.Data.Object
	if err := validateExternalID(obj.ID); err != nil {
		return WebhookEvent{}, err
	}
	st, err := mapStripeStatus(obj.Status)
	if err != nil {
		return WebhookEvent{}, err
	}
	return WebhookEvent{
		ExternalID: obj.ID,
		Status:     st,
		EventType:  envelope.Type,
	}, nil
}

func mapStripeStatus(raw string) (Status, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "requires_input", "processing", "requires_action":
		return StatusPending, nil
	case "verified", "succeeded":
		return StatusApproved, nil
	case "canceled", "failed":
		return StatusRejected, nil
	default:
		if raw == "" {
			return StatusPending, nil
		}
		return StatusPending, nil
	}
}
