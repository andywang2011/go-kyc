package kyc

import (
	"errors"
	"strings"
	"time"
)

const (
	defaultAliyunRealNameBaseURL = "https://cloudauth.aliyuncs.com"
	// Doc: https://help.aliyun.com/document_detail/154606.html
	aliyunInitVerifyPath = "/api/InitFaceVerify"

	defaultStripeIdentityBaseURL = "https://api.stripe.com"
	// Doc: https://docs.stripe.com/api/identity/verification_sessions
	stripeCreateSessionPath = "/v1/identity/verification_sessions"

	defaultPersonaBaseURL = "https://withpersona.com"
	// Doc: https://docs.withpersona.com/reference/create-an-inquiry
	personaCreateInquiryPath = "/api/v1/inquiries"
)

// FakeConfig configures the in-memory Fake provider.
type FakeConfig struct {
	// BaseRedirectURL is prepended to session paths in StartResult.RedirectURL.
	BaseRedirectURL string
}

// AliyunRealNameConfig holds Alibaba Cloud real-name / face verify API settings.
type AliyunRealNameConfig struct {
	// AccessKeyID is the Alibaba Cloud access key ID.
	AccessKeyID string
	// AccessKeySecret is the Alibaba Cloud access key secret.
	AccessKeySecret string
	// SceneID is the cloud auth scene identifier (required).
	SceneID string
	// BaseURL overrides the API base URL (for httptest).
	BaseURL string
	// HTTPClient is the HTTP client used for requests; nil uses a client with a 10s timeout.
	HTTPClient HTTPDoer
}

// Validate checks required Aliyun fields.
func (c AliyunRealNameConfig) Validate() error {
	if strings.TrimSpace(c.AccessKeyID) == "" {
		return errors.New("aliyun access key id is not set")
	}
	if strings.TrimSpace(c.AccessKeySecret) == "" {
		return errors.New("aliyun access key secret is not set")
	}
	if strings.TrimSpace(c.SceneID) == "" {
		return errors.New("aliyun scene id is not set")
	}
	return nil
}

func (c AliyunRealNameConfig) resolvedBaseURL() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultAliyunRealNameBaseURL
}

// StripeIdentityConfig holds Stripe Identity API credentials.
type StripeIdentityConfig struct {
	// SecretKey is the Stripe secret API key (required).
	SecretKey string
	// WebhookSecret is used to verify Stripe-Signature on webhooks. It is optional for
	// Start/Status, but VerifyWebhook returns ErrWebhookUnverifiable when it is empty.
	WebhookSecret string
	// WebhookTolerance is the maximum age or clock skew of a signed webhook timestamp.
	// Zero uses the default of 5 minutes; a negative value disables the timestamp check.
	WebhookTolerance time.Duration
	// BaseURL overrides the Stripe API base URL (for httptest).
	BaseURL string
	// HTTPClient is the HTTP client used for requests; nil uses a client with a 10s timeout.
	HTTPClient HTTPDoer
}

// Validate checks required Stripe fields.
func (c StripeIdentityConfig) Validate() error {
	if strings.TrimSpace(c.SecretKey) == "" {
		return errors.New("stripe secret key is not set")
	}
	return nil
}

func (c StripeIdentityConfig) resolvedBaseURL() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultStripeIdentityBaseURL
}

// PersonaConfig holds Persona inquiry API credentials.
type PersonaConfig struct {
	// APIKey is the Persona API key (required).
	APIKey string
	// TemplateID is the inquiry template ID (required).
	TemplateID string
	// WebhookSecret verifies Persona-Signature headers. VerifyWebhook returns
	// ErrWebhookUnverifiable when it is empty.
	WebhookSecret string
	// WebhookTolerance is the maximum age or clock skew of a signed webhook timestamp.
	// Zero uses the default of 5 minutes; a negative value disables the timestamp check.
	WebhookTolerance time.Duration
	// BaseURL overrides the Persona API base URL (for httptest).
	BaseURL string
	// HTTPClient is the HTTP client used for requests; nil uses a client with a 10s timeout.
	HTTPClient HTTPDoer
}

// Validate checks required Persona fields.
func (c PersonaConfig) Validate() error {
	if strings.TrimSpace(c.APIKey) == "" {
		return errors.New("persona api key is not set")
	}
	if strings.TrimSpace(c.TemplateID) == "" {
		return errors.New("persona template id is not set")
	}
	return nil
}

func (c PersonaConfig) resolvedBaseURL() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultPersonaBaseURL
}
