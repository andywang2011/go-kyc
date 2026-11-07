package kyc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

type fakeSession struct {
	subjectID string
	status    Status
}

type fakeProvider struct {
	baseURL  string
	mu       sync.RWMutex
	sessions map[string]*fakeSession
	seq      atomic.Uint64
}

// NewFake creates an in-memory KYC provider for tests and local development.
func NewFake(cfg FakeConfig) Provider {
	base := strings.TrimRight(cfg.BaseRedirectURL, "/")
	if base == "" {
		base = "https://fake-kyc.test"
	}
	return &fakeProvider{
		baseURL:  base,
		sessions: make(map[string]*fakeSession),
	}
}

// Start registers a pending session and returns a redirect URL.
func (p *fakeProvider) Start(_ context.Context, req StartRequest) (StartResult, error) {
	if err := validateStartRequest(req); err != nil {
		return StartResult{}, err
	}
	id := fmt.Sprintf("fake_%d", p.seq.Add(1))
	p.mu.Lock()
	p.sessions[id] = &fakeSession{subjectID: req.SubjectID, status: StatusPending}
	p.mu.Unlock()
	return StartResult{
		ExternalID:  id,
		RedirectURL: p.baseURL + "/verify/" + id + "?return=" + req.ReturnURL,
	}, nil
}

// Status returns the stored session status.
func (p *fakeProvider) Status(_ context.Context, externalID string) (StatusResult, error) {
	if err := validateExternalID(externalID); err != nil {
		return StatusResult{}, err
	}
	p.mu.RLock()
	sess, ok := p.sessions[externalID]
	p.mu.RUnlock()
	if !ok {
		return StatusResult{}, errors.New("kyc session not found")
	}
	return StatusResult{ExternalID: externalID, Status: sess.status}, nil
}

// VerifyWebhook parses JSON {"external_id":"...","status":"approved","event_type":"..."}.
func (p *fakeProvider) VerifyWebhook(_ context.Context, _ http.Header, body []byte) (WebhookEvent, error) {
	var payload struct {
		ExternalID string `json:"external_id"`
		Status     string `json:"status"`
		EventType  string `json:"event_type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return WebhookEvent{}, fmt.Errorf("fake webhook decode: %w", err)
	}
	if err := validateExternalID(payload.ExternalID); err != nil {
		return WebhookEvent{}, err
	}
	st, err := parseStatus(payload.Status)
	if err != nil {
		return WebhookEvent{}, err
	}
	p.mu.Lock()
	if sess, ok := p.sessions[payload.ExternalID]; ok {
		sess.status = st
	}
	p.mu.Unlock()
	return WebhookEvent{
		ExternalID: payload.ExternalID,
		Status:     st,
		EventType:  payload.EventType,
	}, nil
}

// SetFakeStatus updates a session status (test helper exported for downstream tests).
func SetFakeStatus(p Provider, externalID string, status Status) error {
	fp, ok := p.(*fakeProvider)
	if !ok {
		return errors.New("provider is not fake")
	}
	if err := validateExternalID(externalID); err != nil {
		return err
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	sess, ok := fp.sessions[externalID]
	if !ok {
		return errors.New("kyc session not found")
	}
	sess.status = status
	return nil
}
