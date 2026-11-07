package kyc

import "testing"

func TestProviderConfigsValidate(t *testing.T) {
	if err := (AliyunRealNameConfig{}).Validate(); err == nil {
		t.Fatal("aliyun")
	}
	if err := (StripeIdentityConfig{}).Validate(); err == nil {
		t.Fatal("stripe")
	}
	if err := (PersonaConfig{}).Validate(); err == nil {
		t.Fatal("persona")
	}
}

func TestParseStatus(t *testing.T) {
	st, err := parseStatus("approved")
	if err != nil || st != StatusApproved {
		t.Fatalf("parseStatus() = %q, %v", st, err)
	}
	if _, err := parseStatus("unknown"); err == nil {
		t.Fatal("expected error")
	}
}
