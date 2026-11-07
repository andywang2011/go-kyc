package kyc

import (
	"net/http"
	"testing"
	"time"
)

func TestDefaultHTTPClient_HasTimeout(t *testing.T) {
	c := defaultHTTPClient()
	if c == http.DefaultClient {
		t.Fatal("must not return http.DefaultClient")
	}
	if c.Timeout != 10*time.Second {
		t.Fatalf("Timeout = %v, want 10s", c.Timeout)
	}
	if defaultHTTPClient() == c {
		t.Fatal("each call must return a fresh client")
	}
}

func TestNew_DefaultHTTPClientHasTimeout(t *testing.T) {
	st, err := NewStripeIdentity(StripeIdentityConfig{SecretKey: "sk", WebhookSecret: "wh"})
	if err != nil {
		t.Fatal(err)
	}
	assertTimeout(t, "stripe", st.(*stripeIdentityProvider).client)

	pe, err := NewPersona(PersonaConfig{APIKey: "k", TemplateID: "t", WebhookSecret: "w"})
	if err != nil {
		t.Fatal(err)
	}
	assertTimeout(t, "persona", pe.(*personaProvider).client)

	al, err := NewAliyunRealName(AliyunRealNameConfig{AccessKeyID: "id", AccessKeySecret: "s", SceneID: "sc"})
	if err != nil {
		t.Fatal(err)
	}
	assertTimeout(t, "aliyun", al.(*aliyunRealNameProvider).client)
}

func assertTimeout(t *testing.T, name string, d HTTPDoer) {
	t.Helper()
	c, ok := d.(*http.Client)
	if !ok || c == http.DefaultClient || c.Timeout != 10*time.Second {
		t.Fatalf("%s default client = %#v, want *http.Client with 10s timeout", name, d)
	}
}
