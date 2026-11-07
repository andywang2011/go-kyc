package kyc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewPersonaInvalidConfig(t *testing.T) {
	_, err := NewPersona(PersonaConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPersonaStartStatusWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == personaCreateInquiryPath:
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer key_") {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			_, _ = io.WriteString(w, `{"data":{"id":"inq_1","attributes":{"redirect-uri":"https://persona.test/r","status":"pending"}}}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, personaCreateInquiryPath+"/"):
			_, _ = io.WriteString(w, `{"data":{"id":"inq_1","attributes":{"status":"approved"}}}`)
		default:
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	p, err := NewPersona(PersonaConfig{
		APIKey: "key_live", TemplateID: "itmpl_1", WebhookSecret: "whsec_persona",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	start, err := p.Start(context.Background(), StartRequest{SubjectID: "sub", ReturnURL: "https://cb", Locale: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	if start.ExternalID != "inq_1" {
		t.Fatalf("start = %+v", start)
	}

	st, err := p.Status(context.Background(), "inq_1")
	if err != nil || st.Status != StatusApproved {
		t.Fatalf("Status() = %+v, %v", st, err)
	}

	h := http.Header{}
	webhookBody := []byte(`{"data":{"id":"inq_1","attributes":{"status":"declined"}},"event_type":"inquiry.declined"}`)
	h.Set("Persona-Signature", signTimestamped("whsec_persona", time.Now().Unix(), webhookBody))
	ev, err := p.VerifyWebhook(context.Background(), h, webhookBody)
	if err != nil || ev.Status != StatusRejected {
		t.Fatalf("VerifyWebhook() = %+v, %v", ev, err)
	}
}

func TestPersonaWebhookRequiresSignatureWhenConfigured(t *testing.T) {
	p, _ := NewPersona(PersonaConfig{APIKey: "k", TemplateID: "t", WebhookSecret: "secret"})
	_, err := p.VerifyWebhook(context.Background(), http.Header{}, []byte(`{"data":{"id":"x","attributes":{"status":"pending"}}}`))
	if err == nil {
		t.Fatal("expected signature error")
	}
}

const personaWebhookBody = `{"data":{"id":"inq_1","attributes":{"status":"approved"}},"event_type":"inquiry.approved"}`

func newPersonaWithClock(t *testing.T, secret string, tolerance time.Duration, now time.Time) Provider {
	t.Helper()
	p, err := NewPersona(PersonaConfig{APIKey: "k", TemplateID: "t", WebhookSecret: secret, WebhookTolerance: tolerance})
	if err != nil {
		t.Fatal(err)
	}
	p.(*personaProvider).now = func() time.Time { return now }
	return p
}

func TestPersonaWebhookSignatures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(personaWebhookBody)
	valid := signTimestamped("whsec", now.Unix(), body)
	rotated := signTimestamped("old", now.Unix(), body) + " " + valid
	_, goodMAC, _ := strings.Cut(valid, "v1=")

	tests := []struct {
		name      string
		secret    string
		tolerance time.Duration
		header    string
		wantErr   error
	}{
		{name: "valid", secret: "whsec", header: valid},
		{name: "valid rotated signatures", secret: "whsec", header: rotated},
		{name: "valid, tolerance disabled", secret: "whsec", tolerance: -1, header: signTimestamped("whsec", now.Unix()-86400, body)},
		{name: "missing header", secret: "whsec", header: "", wantErr: ErrWebhookSignatureMissing},
		{name: "forged wrong secret", secret: "whsec", header: signTimestamped("evil", now.Unix(), body), wantErr: ErrWebhookSignatureInvalid},
		{name: "forged body mismatch", secret: "whsec", header: signTimestamped("whsec", now.Unix(), []byte(`{}`)), wantErr: ErrWebhookSignatureInvalid},
		{name: "forged opaque value", secret: "whsec", header: "sig", wantErr: ErrWebhookSignatureInvalid},
		{name: "missing timestamp", secret: "whsec", header: "v1=" + goodMAC, wantErr: ErrWebhookSignatureInvalid},
		{name: "bad timestamp", secret: "whsec", header: "t=x,v1=" + goodMAC, wantErr: ErrWebhookSignatureInvalid},
		{name: "stale timestamp", secret: "whsec", header: signTimestamped("whsec", now.Unix()-301, body), wantErr: ErrWebhookTimestampOutOfTolerance},
		{name: "no secret configured", secret: "", header: valid, wantErr: ErrWebhookUnverifiable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPersonaWithClock(t, tt.secret, tt.tolerance, now)
			h := http.Header{}
			if tt.header != "" {
				h.Set("Persona-Signature", tt.header)
			}
			ev, err := p.VerifyWebhook(context.Background(), h, body)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if ev != (WebhookEvent{}) {
					t.Fatalf("event must be empty on error, got %+v", ev)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ev.ExternalID != "inq_1" || ev.Status != StatusApproved || ev.EventType != "inquiry.approved" {
				t.Fatalf("event = %+v", ev)
			}
		})
	}
}
