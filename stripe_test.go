package kyc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewStripeIdentityInvalidConfig(t *testing.T) {
	_, err := NewStripeIdentity(StripeIdentityConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStripeStartStatusWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == stripeCreateSessionPath:
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer sk_") {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			_, _ = io.WriteString(w, `{"id":"vs_123","url":"https://stripe.test/verify","status":"requires_input"}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, stripeCreateSessionPath+"/"):
			_, _ = io.WriteString(w, `{"id":"vs_123","status":"verified"}`)
		default:
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	p, err := NewStripeIdentity(StripeIdentityConfig{
		SecretKey:     "sk_test",
		WebhookSecret: "whsec_test",
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	start, err := p.Start(context.Background(), StartRequest{SubjectID: "u1", ReturnURL: "https://cb"})
	if err != nil {
		t.Fatal(err)
	}
	if start.ExternalID != "vs_123" {
		t.Fatalf("start = %+v", start)
	}

	st, err := p.Status(context.Background(), "vs_123")
	if err != nil || st.Status != StatusApproved {
		t.Fatalf("Status() = %+v, %v", st, err)
	}

	webhookBody := []byte(`{"type":"identity.verification_session.verified","data":{"object":{"id":"vs_123","status":"verified"}}}`)
	h := http.Header{}
	h.Set("Stripe-Signature", signTimestamped("whsec_test", time.Now().Unix(), webhookBody))
	ev, err := p.VerifyWebhook(context.Background(), h, webhookBody)
	if err != nil || ev.Status != StatusApproved {
		t.Fatalf("VerifyWebhook() = %+v, %v", ev, err)
	}
}

func TestStripeWebhookMissingSignature(t *testing.T) {
	p, _ := NewStripeIdentity(StripeIdentityConfig{SecretKey: "sk", WebhookSecret: "whsec"})
	_, err := p.VerifyWebhook(context.Background(), http.Header{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected signature error")
	}
}

// signTimestamped builds a "t=<unix>,v1=<hex>" header for the given secret and body.
func signTimestamped(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d.", ts)
	_, _ = mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func newStripeWithClock(t *testing.T, secret string, tolerance time.Duration, now time.Time) Provider {
	t.Helper()
	p, err := NewStripeIdentity(StripeIdentityConfig{SecretKey: "sk", WebhookSecret: secret, WebhookTolerance: tolerance})
	if err != nil {
		t.Fatal(err)
	}
	p.(*stripeIdentityProvider).now = func() time.Time { return now }
	return p
}

const stripeWebhookBody = `{"type":"identity.verification_session.verified","data":{"object":{"id":"vs_1","status":"verified"}}}`

func TestStripeWebhookSignatures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(stripeWebhookBody)
	valid := signTimestamped("whsec", now.Unix(), body)
	other := signTimestamped("other", now.Unix(), body)
	tampered := signTimestamped("whsec", now.Unix(), []byte(`{"tampered":true}`))
	_, goodMAC, _ := strings.Cut(valid, "v1=")

	tests := []struct {
		name      string
		secret    string
		tolerance time.Duration
		header    string
		wantErr   error
	}{
		{name: "valid", secret: "whsec", header: valid},
		{name: "valid with rotated extra v1", secret: "whsec", header: valid + ",v1=deadbeef"},
		{name: "valid within tolerance", secret: "whsec", header: signTimestamped("whsec", now.Unix()-299, body)},
		{name: "valid old timestamp, tolerance disabled", secret: "whsec", tolerance: -1, header: signTimestamped("whsec", now.Unix()-86400, body)},
		{name: "missing header", secret: "whsec", header: "", wantErr: ErrWebhookSignatureMissing},
		{name: "blank header", secret: "whsec", header: "   ", wantErr: ErrWebhookSignatureMissing},
		{name: "forged with wrong secret", secret: "whsec", header: other, wantErr: ErrWebhookSignatureInvalid},
		{name: "forged body mismatch", secret: "whsec", header: tampered, wantErr: ErrWebhookSignatureInvalid},
		{name: "forged arbitrary v1", secret: "whsec", header: "t=1,v1=abc", wantErr: ErrWebhookSignatureInvalid},
		{name: "non-hex v1", secret: "whsec", header: fmt.Sprintf("t=%d,v1=zzzz", now.Unix()), wantErr: ErrWebhookSignatureInvalid},
		{name: "missing timestamp", secret: "whsec", header: "v1=" + goodMAC, wantErr: ErrWebhookSignatureInvalid},
		{name: "missing v1", secret: "whsec", header: fmt.Sprintf("t=%d", now.Unix()), wantErr: ErrWebhookSignatureInvalid},
		{name: "bad timestamp", secret: "whsec", header: "t=abc,v1=" + goodMAC, wantErr: ErrWebhookSignatureInvalid},
		{name: "timestamp spoofed after signing", secret: "whsec", header: fmt.Sprintf("t=%d,v1=%s", now.Unix()+1, goodMAC), wantErr: ErrWebhookSignatureInvalid},
		{name: "stale timestamp", secret: "whsec", header: signTimestamped("whsec", now.Unix()-301, body), wantErr: ErrWebhookTimestampOutOfTolerance},
		{name: "future timestamp", secret: "whsec", header: signTimestamped("whsec", now.Unix()+301, body), wantErr: ErrWebhookTimestampOutOfTolerance},
		{name: "custom tolerance exceeded", secret: "whsec", tolerance: time.Second, header: signTimestamped("whsec", now.Unix()-2, body), wantErr: ErrWebhookTimestampOutOfTolerance},
		{name: "no secret configured", secret: "", header: valid, wantErr: ErrWebhookUnverifiable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newStripeWithClock(t, tt.secret, tt.tolerance, now)
			h := http.Header{}
			if tt.header != "" {
				h.Set("Stripe-Signature", tt.header)
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
			if ev.ExternalID != "vs_1" || ev.Status != StatusApproved {
				t.Fatalf("event = %+v", ev)
			}
		})
	}
}
