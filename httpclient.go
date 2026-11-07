package kyc

import (
	"net/http"
	"time"
)

const defaultHTTPTimeout = 10 * time.Second

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}
