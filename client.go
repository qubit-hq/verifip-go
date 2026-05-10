package verifip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL   = "https://api.verifip.com"
	defaultTimeout   = 30 * time.Second
	defaultMaxRetries = 3
	sdkVersion       = "0.2.0"
	userAgent        = "verifip-go/" + sdkVersion
)

// Client is the VerifIP API client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
	rateLimit  *RateLimitInfo
	mu         sync.RWMutex
}

// Option configures the Client.
type Option func(*Client)

// WithBaseURL sets a custom base URL for the API.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithMaxRetries sets the maximum number of retries for failed requests.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		c.maxRetries = n
	}
}

// NewClient creates a new VerifIP API client.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
		maxRetries: defaultMaxRetries,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Check performs a single IP fraud check.
func (c *Client) Check(ctx context.Context, ip string) (*CheckResponse, error) {
	u := fmt.Sprintf("%s/v1/check?ip=%s", c.baseURL, url.QueryEscape(ip))

	var result CheckResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckBatch performs a batch IP fraud check for up to 100 IPs.
func (c *Client) CheckBatch(ctx context.Context, ips []string) (*BatchResponse, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("verifip: batch request must contain at least 1 IP")
	}
	if len(ips) > 100 {
		return nil, fmt.Errorf("verifip: batch request must contain at most 100 IPs, got %d", len(ips))
	}

	body := BatchRequest{IPs: ips}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("verifip: failed to encode request body: %w", err)
	}

	u := fmt.Sprintf("%s/v1/check/batch", c.baseURL)

	var result BatchResponse
	if err := c.request(ctx, http.MethodPost, u, encoded, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// Health returns the API health status. No authentication is required.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	u := fmt.Sprintf("%s/health", c.baseURL)

	var result HealthResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, false); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckEmail performs an email risk check.
func (c *Client) CheckEmail(ctx context.Context, email string) (*EmailResponse, error) {
	u := fmt.Sprintf("%s/v1/email?email=%s", c.baseURL, url.QueryEscape(email))

	var result EmailResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckPhone performs a phone number risk check.
func (c *Client) CheckPhone(ctx context.Context, phone string) (*PhoneResponse, error) {
	u := fmt.Sprintf("%s/v1/phone?phone=%s", c.baseURL, url.QueryEscape(phone))

	var result PhoneResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckURL performs a URL risk check.
func (c *Client) CheckURL(ctx context.Context, rawURL string) (*URLResponse, error) {
	u := fmt.Sprintf("%s/v1/url?url=%s", c.baseURL, url.QueryEscape(rawURL))

	var result URLResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckWHOIS performs a WHOIS lookup for an IP address.
func (c *Client) CheckWHOIS(ctx context.Context, ip string) (*WHOISResponse, error) {
	u := fmt.Sprintf("%s/v1/whois?ip=%s", c.baseURL, url.QueryEscape(ip))

	var result WHOISResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// Report submits a fraud report for an IP address.
func (c *Client) Report(ctx context.Context, ip string, isFraud bool, category, comment string) (*ReportResponse, error) {
	body := ReportRequest{IP: ip, IsFraud: isFraud}
	if category != "" {
		body.Category = category
	}
	if comment != "" {
		body.Comment = comment
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("verifip: failed to encode request body: %w", err)
	}

	u := fmt.Sprintf("%s/v1/report", c.baseURL)

	var result ReportResponse
	if err := c.request(ctx, http.MethodPost, u, encoded, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// Assess performs a multi-signal risk assessment.
func (c *Client) Assess(ctx context.Context, ip, email, phone, urlStr string) (*AssessResponse, error) {
	params := url.Values{}
	if ip != "" {
		params.Set("ip", ip)
	}
	if email != "" {
		params.Set("email", email)
	}
	if phone != "" {
		params.Set("phone", phone)
	}
	if urlStr != "" {
		params.Set("url", urlStr)
	}
	if len(params) == 0 {
		return nil, fmt.Errorf("verifip: at least one parameter is required")
	}

	u := fmt.Sprintf("%s/v1/assess?%s", c.baseURL, params.Encode())

	var result AssessResponse
	if err := c.request(ctx, http.MethodGet, u, nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

// RateLimit returns the most recently observed rate limit information,
// or nil if no rate limit headers have been received yet.
func (c *Client) RateLimit() *RateLimitInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rateLimit == nil {
		return nil
	}
	rl := *c.rateLimit
	return &rl
}

// request performs an HTTP request with retries and exponential backoff.
func (c *Client) request(ctx context.Context, method, rawURL string, body []byte, dest any, auth bool) error {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			wait := backoff + jitter

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = strings.NewReader(string(body))
		}

		req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
		if err != nil {
			return fmt.Errorf("verifip: failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if auth {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("verifip: request failed: %w", err)
			continue
		}

		c.parseRateLimitHeaders(resp)

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("verifip: failed to read response body: %w", err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if err := json.Unmarshal(respBody, dest); err != nil {
				return fmt.Errorf("verifip: failed to decode response: %w", err)
			}
			return nil
		}

		apiErr := &APIError{StatusCode: resp.StatusCode}

		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil {
			apiErr.ErrorCode = errResp.Error
			apiErr.Message = errResp.Message
			apiErr.RetryAfter = errResp.RetryAfter
		}

		// Retry on 429 and 5xx
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = apiErr
			continue
		}

		return apiErr
	}

	return fmt.Errorf("verifip: max retries exceeded: %w", lastErr)
}

// parseRateLimitHeaders extracts rate limit info from response headers.
func (c *Client) parseRateLimitHeaders(resp *http.Response) {
	limitStr := resp.Header.Get("X-RateLimit-Limit")
	remainingStr := resp.Header.Get("X-RateLimit-Remaining")
	resetStr := resp.Header.Get("X-RateLimit-Reset")

	if limitStr == "" && remainingStr == "" && resetStr == "" {
		return
	}

	rl := &RateLimitInfo{}

	if v, err := strconv.Atoi(limitStr); err == nil {
		rl.Limit = v
	}
	if v, err := strconv.Atoi(remainingStr); err == nil {
		rl.Remaining = v
	}
	if v, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
		rl.Reset = time.Unix(v, 0)
	}

	c.mu.Lock()
	c.rateLimit = rl
	c.mu.Unlock()
}
