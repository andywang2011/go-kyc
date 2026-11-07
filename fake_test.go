package kyc

import (
	"context"
	"testing"
)

func TestFakeStartStatusWebhook(t *testing.T) {
	p := NewFake(FakeConfig{BaseRedirectURL: "https://example.test"})
	ctx := context.Background()

	start, err := p.Start(ctx, StartRequest{SubjectID: "user-1", ReturnURL: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if start.ExternalID == "" || start.RedirectURL == "" {
		t.Fatalf("start = %+v", start)
	}

	st, err := p.Status(ctx, start.ExternalID)
	if err != nil || st.Status != StatusPending {
		t.Fatalf("Status() = %+v, %v", st, err)
	}

	ev, err := p.VerifyWebhook(ctx, nil, []byte(`{"external_id":"`+start.ExternalID+`","status":"approved","event_type":"done"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != StatusApproved {
		t.Fatalf("event = %+v", ev)
	}

	st, err = p.Status(ctx, start.ExternalID)
	if err != nil || st.Status != StatusApproved {
		t.Fatalf("Status() after webhook = %+v, %v", st, err)
	}
}

func TestSetFakeStatus(t *testing.T) {
	p := NewFake(FakeConfig{})
	ctx := context.Background()
	start, _ := p.Start(ctx, StartRequest{SubjectID: "u", ReturnURL: "https://r"})
	if err := SetFakeStatus(p, start.ExternalID, StatusRejected); err != nil {
		t.Fatal(err)
	}
	st, _ := p.Status(ctx, start.ExternalID)
	if st.Status != StatusRejected {
		t.Fatalf("status = %s", st.Status)
	}
}

func TestFakeValidation(t *testing.T) {
	p := NewFake(FakeConfig{})
	if _, err := p.Start(context.Background(), StartRequest{}); err == nil {
		t.Fatal("expected start validation error")
	}
	if _, err := p.Status(context.Background(), ""); err == nil {
		t.Fatal("expected status validation error")
	}
}
