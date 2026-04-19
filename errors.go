package verifip

import (
	"errors"
	"fmt"
	"net/http"
)

// APIError represents an error returned by the VerifIP API.
type APIError struct {
	StatusCode int
	ErrorCode  string
	Message    string
	RetryAfter int
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("verifip: HTTP %d: %s — %s", e.StatusCode, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("verifip: HTTP %d: %s", e.StatusCode, e.ErrorCode)
}

// IsRateLimitError reports whether err is a rate-limit (429) error.
func IsRateLimitError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// IsAuthError reports whether err is an authentication (401) error.
func IsAuthError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusUnauthorized
	}
	return false
}
