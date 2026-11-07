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
)

func TestNewAliyunRealNameInvalidConfig(t *testing.T) {
	_, err := NewAliyunRealName(AliyunRealNameConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAliyunStartAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case aliyunInitVerifyPath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["SceneId"] != "scene-1" {
				t.Errorf("SceneId = %q", body["SceneId"])
			}
			_, _ = io.WriteString(w, `{"Code":"200","ResultObject":{"CertifyId":"cert-1","CertifyUrl":"https://verify"}}`)
		case "/api/DescribeFaceVerify":
			_, _ = io.WriteString(w, `{"ResultObject":{"Passed":"y"}}`)
		default:
			t.Errorf("path = %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	p, err := NewAliyunRealName(AliyunRealNameConfig{
		AccessKeyID: "id", AccessKeySecret: "secret", SceneID: "scene-1",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	start, err := p.Start(context.Background(), StartRequest{SubjectID: "sub", ReturnURL: "https://return"})
	if err != nil {
		t.Fatal(err)
	}
	if start.ExternalID != "cert-1" {
		t.Fatalf("start = %+v", start)
	}

	st, err := p.Status(context.Background(), "cert-1")
	if err != nil || st.Status != StatusApproved {
		t.Fatalf("Status() = %+v, %v", st, err)
	}
}

func TestAliyunWebhook(t *testing.T) {
	p, err := NewAliyunRealName(AliyunRealNameConfig{AccessKeyID: "a", AccessKeySecret: "b", SceneID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "anything")
	for _, headers := range []http.Header{nil, h} {
		ev, err := p.VerifyWebhook(context.Background(), headers, []byte(`{"CertifyId":"x","Passed":"y","EventType":"verify"}`))
		if !errors.Is(err, ErrWebhookUnverifiable) {
			t.Fatalf("VerifyWebhook() err = %v, want ErrWebhookUnverifiable", err)
		}
		if ev != (WebhookEvent{}) {
			t.Fatalf("event must be empty, got %+v", ev)
		}
	}
}

func TestAliyunStartHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"Message":"bad"}`)
	}))
	t.Cleanup(srv.Close)

	p, _ := NewAliyunRealName(AliyunRealNameConfig{
		AccessKeyID: "a", AccessKeySecret: "b", SceneID: "c",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	_, err := p.Start(context.Background(), StartRequest{SubjectID: "s", ReturnURL: "https://r"})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("Start() = %v", err)
	}
}
