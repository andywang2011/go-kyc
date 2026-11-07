// Package kyc provides identity verification providers with config injection.
//
// Design constraints:
//   - No viper, environment variables, or config file paths inside the library.
//   - No global singletons or log.Fatal; callers construct providers via New*.
//   - HTTP providers accept an optional HTTP client in Config for httptest.
//   - New* returns Provider (client_iface.go) for mocks and dependency injection.
//   - ConfigDefault: N/A — each backend uses its own *Config struct (AliyunRealNameConfig, etc.).
package kyc
