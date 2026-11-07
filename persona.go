package kyc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type personaProvider struct {
	apiKey           string
	templateID       string
	webhookSecret    string
	webhookTolerance time.Duration
	baseURL          string
	client           HTTPDoer
	now              func() time.Time
}

// NewPersona creates a Persona inquiry provider stub.
func NewPersona(cfg PersonaConfig) (Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	return &personaProvider{
		apiKey:           cfg.APIKey,
		templateID:       cfg.TemplateID,
		webhookSecret:    cfg.WebhookSecret,
		webhookTolerance: cfg.WebhookTolerance,
		baseURL:          cfg.resolvedBaseURL(),
		client:           client,
		now:              time.Now,
	}, nil
}

// Start creates a Persona inquiry.
func (p *personaProvider) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if err := validateStartRequest(req); err != nil {
		return StartResult{}, err
	}

	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "inquiry",
			"attributes": map[string]interface{}{
				"inquiry-template-id": p.templateID,
				"reference-id":        req.SubjectID,
				"redirect-uri":        req.ReturnURL,
			},
		},
	}
	if req.Locale != "" {
		payload["data"].(map[string]interface{})["attributes"].(map[string]interface{})["locale"] = req.Locale
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return StartResult{}, fmt.Errorf("persona encode request: %w", err)
	}

	reqURL := p.baseURL + personaCreateInquiryPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return StartResult{}, fmt.Errorf("persona create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StartResult{}, fmt.Errorf("persona request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StartResult{}, fmt.Errorf("persona api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				RedirectURI string `json:"redirect-uri"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StartResult{}, fmt.Errorf("persona decode response: %w", err)
	}
	if parsed.Data.ID == "" {
		return StartResult{}, fmt.Errorf("persona missing inquiry id")
	}
	return StartResult{
		ExternalID:  parsed.Data.ID,
		RedirectURL: parsed.Data.Attributes.RedirectURI,
	}, nil
}

// Status fetches inquiry status by ID.
func (p *personaProvider) Status(ctx context.Context, externalID string) (StatusResult, error) {
	if err := validateExternalID(externalID); err != nil {
		return StatusResult{}, err
	}

	reqURL := p.baseURL + personaCreateInquiryPath + "/" + externalID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return StatusResult{}, fmt.Errorf("persona create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StatusResult{}, fmt.Errorf("persona request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StatusResult{}, fmt.Errorf("persona api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Status string `json:"status"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StatusResult{}, fmt.Errorf("persona decode response: %w", err)
	}
	st, err := mapPersonaStatus(parsed.Data.Attributes.Status)
	if err != nil {
		return StatusResult{}, err
	}
	return StatusResult{ExternalID: parsed.Data.ID, Status: st}, nil
}

// VerifyWebhook verifies the Persona-Signature header (t=<unix>,v1=<hex>) using
// HMAC-SHA256 over "<timestamp>.<payload>" with the webhook secret, enforces the
// timestamp tolerance, and then parses the inquiry event. Multiple space-separated
// signatures (secret rotation) are accepted if any one matches.
// It returns ErrWebhookUnverifiable when no webhook secret is configured.
func (p *personaProvider) VerifyWebhook(_ context.Context, headers http.Header, body []byte) (WebhookEvent, error) {
	if err := verifyTimestampedHMAC(p.webhookSecret, headers.Get("Persona-Signature"), body, p.webhookTolerance, p.now()); err != nil {
		return WebhookEvent{}, fmt.Errorf("persona webhook: %w", err)
	}

	var payload struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Status string `json:"status"`
			} `json:"attributes"`
		} `json:"data"`
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return WebhookEvent{}, fmt.Errorf("persona webhook decode: %w", err)
	}
	if err := validateExternalID(payload.Data.ID); err != nil {
		return WebhookEvent{}, err
	}
	st, err := mapPersonaStatus(payload.Data.Attributes.Status)
	if err != nil {
		return WebhookEvent{}, err
	}
	evType := payload.EventType
	if evType == "" {
		evType = headers.Get("Persona-Event-Type")
	}
	return WebhookEvent{
		ExternalID: payload.Data.ID,
		Status:     st,
		EventType:  evType,
	}, nil
}

func mapPersonaStatus(raw string) (Status, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pending", "created", "started", "in_progress":
		return StatusPending, nil
	case "completed", "approved", "passed":
		return StatusApproved, nil
	case "failed", "declined", "rejected", "expired":
		return StatusRejected, nil
	case "":
		return StatusPending, nil
	default:
		return StatusPending, nil
	}
}
