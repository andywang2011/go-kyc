package kyc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type aliyunRealNameProvider struct {
	accessKeyID     string
	accessKeySecret string
	sceneID         string
	baseURL         string
	client          HTTPDoer
}

// NewAliyunRealName creates an Alibaba Cloud real-name verification provider stub.
func NewAliyunRealName(cfg AliyunRealNameConfig) (Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	return &aliyunRealNameProvider{
		accessKeyID:     cfg.AccessKeyID,
		accessKeySecret: cfg.AccessKeySecret,
		sceneID:         cfg.SceneID,
		baseURL:         cfg.resolvedBaseURL(),
		client:          client,
	}, nil
}

// Start calls InitFaceVerify and returns CertifyUrl when successful.
func (p *aliyunRealNameProvider) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if err := validateStartRequest(req); err != nil {
		return StartResult{}, err
	}

	payload := map[string]string{
		"SceneId":      p.sceneID,
		"OuterOrderNo": req.SubjectID,
		"ReturnUrl":    req.ReturnURL,
	}
	if req.Locale != "" {
		payload["Language"] = req.Locale
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return StartResult{}, fmt.Errorf("aliyun encode request: %w", err)
	}

	reqURL := p.baseURL + aliyunInitVerifyPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return StartResult{}, fmt.Errorf("aliyun create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-acs-accesskey-id", p.accessKeyID)
	httpReq.Header.Set("x-acs-accesskey-secret", p.accessKeySecret)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StartResult{}, fmt.Errorf("aliyun request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StartResult{}, fmt.Errorf("aliyun api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ResultObject struct {
			CertifyID  string `json:"CertifyId"`
			CertifyUrl string `json:"CertifyUrl"`
		} `json:"ResultObject"`
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StartResult{}, fmt.Errorf("aliyun decode response: %w", err)
	}
	if parsed.Code != "" && parsed.Code != "200" {
		msg := parsed.Message
		if msg == "" {
			msg = string(respBody)
		}
		return StartResult{}, fmt.Errorf("aliyun start failed: %s", msg)
	}
	if parsed.ResultObject.CertifyID == "" {
		return StartResult{}, fmt.Errorf("aliyun missing certify id")
	}
	return StartResult{
		ExternalID:  parsed.ResultObject.CertifyID,
		RedirectURL: parsed.ResultObject.CertifyUrl,
	}, nil
}

// Status queries verification status by CertifyId.
func (p *aliyunRealNameProvider) Status(ctx context.Context, externalID string) (StatusResult, error) {
	if err := validateExternalID(externalID); err != nil {
		return StatusResult{}, err
	}

	payload := map[string]string{"CertifyId": externalID}
	body, err := json.Marshal(payload)
	if err != nil {
		return StatusResult{}, err
	}

	reqURL := p.baseURL + "/api/DescribeFaceVerify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return StatusResult{}, fmt.Errorf("aliyun create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-acs-accesskey-id", p.accessKeyID)
	httpReq.Header.Set("x-acs-accesskey-secret", p.accessKeySecret)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return StatusResult{}, fmt.Errorf("aliyun request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StatusResult{}, fmt.Errorf("aliyun api error: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		ResultObject struct {
			Passed string `json:"Passed"`
		} `json:"ResultObject"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return StatusResult{}, fmt.Errorf("aliyun decode response: %w", err)
	}

	st := StatusPending
	switch strings.ToLower(parsed.ResultObject.Passed) {
	case "y", "yes", "true", "1":
		st = StatusApproved
	case "n", "no", "false", "0":
		st = StatusRejected
	}
	return StatusResult{ExternalID: externalID, Status: st}, nil
}

// VerifyWebhook always returns ErrWebhookUnverifiable: Alibaba Cloud real-name
// callbacks carry no signature that this provider can validate, so the origin of
// the request cannot be proven. Callers should confirm the result with Status
// (an authenticated API call) instead of trusting the callback body.
func (p *aliyunRealNameProvider) VerifyWebhook(_ context.Context, _ http.Header, _ []byte) (WebhookEvent, error) {
	return WebhookEvent{}, fmt.Errorf("aliyun webhook: %w", ErrWebhookUnverifiable)
}
