package kyc

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type fakeProviderHook struct {
	startFn   func(context.Context, StartRequest) (StartResult, error)
	statusFn  func(context.Context, string) (StatusResult, error)
	webhookFn func(context.Context, http.Header, []byte) (WebhookEvent, error)
}

func (f fakeProviderHook) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if f.startFn != nil {
		return f.startFn(ctx, req)
	}
	return StartResult{}, nil
}

func (f fakeProviderHook) Status(ctx context.Context, id string) (StatusResult, error) {
	if f.statusFn != nil {
		return f.statusFn(ctx, id)
	}
	return StatusResult{}, nil
}

func (f fakeProviderHook) VerifyWebhook(ctx context.Context, h http.Header, b []byte) (WebhookEvent, error) {
	if f.webhookFn != nil {
		return f.webhookFn(ctx, h, b)
	}
	return WebhookEvent{}, nil
}

func TestFakeProviderPattern(t *testing.T) {
	var called bool
	p := fakeProviderHook{startFn: func(_ context.Context, req StartRequest) (StartResult, error) {
		called = true
		if req.SubjectID == "" {
			return StartResult{}, errors.New("empty")
		}
		return StartResult{ExternalID: "id"}, nil
	}}
	res, err := p.Start(context.Background(), StartRequest{SubjectID: "u", ReturnURL: "https://r"})
	if err != nil || res.ExternalID != "id" || !called {
		t.Fatalf("Start() = %+v, %v, called=%v", res, err, called)
	}
}
