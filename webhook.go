package kyc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// defaultWebhookTolerance is the maximum allowed clock skew between the
// webhook timestamp and the local clock when no tolerance is configured.
const defaultWebhookTolerance = 5 * time.Minute

var (
	// ErrWebhookUnverifiable is returned when the origin of a webhook cannot be
	// proven, for example when no webhook secret is configured or the provider
	// does not offer a signing scheme.
	ErrWebhookUnverifiable = errors.New("kyc webhook origin cannot be verified")
	// ErrWebhookSignatureMissing is returned when the signature header is absent or empty.
	ErrWebhookSignatureMissing = errors.New("kyc webhook signature missing")
	// ErrWebhookSignatureInvalid is returned when the signature header is malformed
	// or does not match the payload.
	ErrWebhookSignatureInvalid = errors.New("kyc webhook signature invalid")
	// ErrWebhookTimestampOutOfTolerance is returned when the signed timestamp is
	// outside the allowed tolerance window.
	ErrWebhookTimestampOutOfTolerance = errors.New("kyc webhook timestamp outside tolerance")
)

// parsedSignature is the decoded form of a "t=<unix>,v1=<hex>" signature header.
type parsedSignature struct {
	timestamp int64
	hasTime   bool
	v1        []string
}

// parseSignatureHeader parses headers of the form "t=1700000000,v1=abcd".
// Elements may be separated by commas or whitespace; multiple v1 values
// (secret rotation) are all collected.
func parseSignatureHeader(header string) (parsedSignature, error) {
	var out parsedSignature
	fields := strings.FieldsFunc(header, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "t":
			ts, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return parsedSignature{}, ErrWebhookSignatureInvalid
			}
			out.timestamp = ts
			out.hasTime = true
		case "v1":
			out.v1 = append(out.v1, strings.TrimSpace(v))
		}
	}
	return out, nil
}

// computeHMACSHA256 returns HMAC-SHA256(secret, message).
func computeHMACSHA256(secret string, message []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

// matchesAnySignature reports whether any hex-encoded candidate equals expected,
// using constant-time comparison.
func matchesAnySignature(expected []byte, candidates []string) bool {
	matched := false
	for _, c := range candidates {
		got, err := hex.DecodeString(c)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, got) {
			matched = true
		}
	}
	return matched
}

// signedPayload builds "<timestamp>.<body>".
func signedPayload(ts int64, body []byte) []byte {
	prefix := strconv.FormatInt(ts, 10) + "."
	out := make([]byte, 0, len(prefix)+len(body))
	out = append(out, prefix...)
	out = append(out, body...)
	return out
}

// verifyTimestampedHMAC verifies a "t=,v1=" header against body.
// A negative tolerance disables the timestamp check; zero uses the default.
func verifyTimestampedHMAC(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	if strings.TrimSpace(secret) == "" {
		return ErrWebhookUnverifiable
	}
	if strings.TrimSpace(header) == "" {
		return ErrWebhookSignatureMissing
	}
	sig, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	if !sig.hasTime || len(sig.v1) == 0 {
		return ErrWebhookSignatureInvalid
	}
	expected := computeHMACSHA256(secret, signedPayload(sig.timestamp, body))
	if !matchesAnySignature(expected, sig.v1) {
		return ErrWebhookSignatureInvalid
	}
	if tolerance == 0 {
		tolerance = defaultWebhookTolerance
	}
	if tolerance > 0 {
		skew := now.Sub(time.Unix(sig.timestamp, 0))
		if skew < 0 {
			skew = -skew
		}
		if skew > tolerance {
			return ErrWebhookTimestampOutOfTolerance
		}
	}
	return nil
}
