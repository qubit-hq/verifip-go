package verifip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	verifip "github.com/qubit-hq/verifip-go"
)

// helper to create a test server and client pointing at it.
func setup(handler http.HandlerFunc) (*httptest.Server, *verifip.Client) {
	srv := httptest.NewServer(handler)
	client := verifip.NewClient("test-key",
		verifip.WithBaseURL(srv.URL),
		verifip.WithMaxRetries(0),
	)
	return srv, client
}

func TestCheck_Success(t *testing.T) {
	srv, client := setup(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/check" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("ip") != "8.8.8.8" {
			t.Errorf("unexpected ip param: %s", r.URL.Query().Get("ip"))
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", auth)
		}
		if ua := r.Header.Get("User-Agent"); ua != "verifip-go/0.1.0" {
			t.Errorf("unexpected user-agent: %s", ua)
		}

		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "999")
		w.Header().Set("X-RateLimit-Reset", "1700000000")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"request_id": "req-123",
			"ip": "8.8.8.8",
			"fraud_score": 12.5,
			"is_proxy": false,
			"is_vpn": false,
			"is_tor": false,
			"is_datacenter": true,
			"country_code": "US",
			"country_name": "United States",
			"region": "California",
			"city": "Mountain View",
			"isp": "Google LLC",
			"asn": 15169,
			"connection_type": "hosting",
			"hostname": "dns.google",
			"signal_breakdown": {"datacenter": 80, "reputation": 10}
		}`)
	})
	defer srv.Close()

	resp, err := client.Check(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.RequestID != "req-123" {
		t.Errorf("request_id = %q, want %q", resp.RequestID, "req-123")
	}
	if resp.FraudScore != 12.5 {
		t.Errorf("fraud_score = %v, want 12.5", resp.FraudScore)
	}
	if !resp.IsDatacenter {
		t.Error("is_datacenter = false, want true")
	}
	if resp.ASN != 15169 {
		t.Errorf("asn = %d, want 15169", resp.ASN)
	}
	if resp.SignalBreakdown["datacenter"] != 80 {
		t.Errorf("signal_breakdown[datacenter] = %d, want 80", resp.SignalBreakdown["datacenter"])
	}
}

func TestCheck_ErrorResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		checkErr   func(t *testing.T, err error)
	}{
		{
			name:   "400 bad request",
			status: http.StatusBadRequest,
			body:   `{"error": "invalid_ip", "message": "not a valid IP address"}`,
			checkErr: func(t *testing.T, err error) {
				if verifip.IsRateLimitError(err) {
					t.Error("should not be rate limit error")
				}
				if verifip.IsAuthError(err) {
					t.Error("should not be auth error")
				}
			},
		},
		{
			name:   "401 unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"error": "unauthorized", "message": "invalid API key"}`,
			checkErr: func(t *testing.T, err error) {
				if !verifip.IsAuthError(err) {
					t.Error("should be auth error")
				}
				if verifip.IsRateLimitError(err) {
					t.Error("should not be rate limit error")
				}
			},
		},
		{
			name:   "429 rate limited",
			status: http.StatusTooManyRequests,
			body:   `{"error": "rate_limited", "message": "slow down", "retry_after": 30}`,
			checkErr: func(t *testing.T, err error) {
				if !verifip.IsRateLimitError(err) {
					t.Error("should be rate limit error")
				}
				if verifip.IsAuthError(err) {
					t.Error("should not be auth error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, client := setup(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			})
			defer srv.Close()

			_, err := client.Check(context.Background(), "1.2.3.4")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			tt.checkErr(t, err)
		})
	}
}

func TestCheckBatch_Success(t *testing.T) {
	srv, client := setup(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/check/batch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"results": [
			{"request_id": "r1", "ip": "1.1.1.1", "fraud_score": 5},
			{"request_id": "r2", "ip": "2.2.2.2", "fraud_score": 90}
		]}`)
	})
	defer srv.Close()

	resp, err := client.CheckBatch(context.Background(), []string{"1.1.1.1", "2.2.2.2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results count = %d, want 2", len(resp.Results))
	}
	if resp.Results[0].IP != "1.1.1.1" {
		t.Errorf("results[0].ip = %q, want %q", resp.Results[0].IP, "1.1.1.1")
	}
	if resp.Results[1].FraudScore != 90 {
		t.Errorf("results[1].fraud_score = %v, want 90", resp.Results[1].FraudScore)
	}
}

func TestCheckBatch_Validation(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
	}{
		{"empty", []string{}},
		{"too many", make([]string, 101)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No server needed; validation happens client-side.
			client := verifip.NewClient("key", verifip.WithBaseURL("http://localhost:0"))
			_, err := client.CheckBatch(context.Background(), tt.ips)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestHealth_Success(t *testing.T) {
	srv, client := setup(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// Health must not send auth header.
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("health should not send auth, got: %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"status": "healthy",
			"version": "1.2.3",
			"data_loaded_at": "2024-01-01T00:00:00Z",
			"redis": "connected",
			"postgres": "connected",
			"uptime_seconds": 3600
		}`)
	})
	defer srv.Close()

	resp, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("status = %q, want %q", resp.Status, "healthy")
	}
	if resp.UptimeSeconds != 3600 {
		t.Errorf("uptime_seconds = %d, want 3600", resp.UptimeSeconds)
	}
}

func TestRateLimitParsing(t *testing.T) {
	resetUnix := int64(1700000000)

	srv, client := setup(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "42")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status": "healthy"}`)
	})
	defer srv.Close()

	// Before any request, RateLimit should be nil.
	if rl := client.RateLimit(); rl != nil {
		t.Errorf("expected nil rate limit before any request, got %+v", rl)
	}

	_, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rl := client.RateLimit()
	if rl == nil {
		t.Fatal("expected rate limit info after request")
	}
	if rl.Limit != 1000 {
		t.Errorf("limit = %d, want 1000", rl.Limit)
	}
	if rl.Remaining != 42 {
		t.Errorf("remaining = %d, want 42", rl.Remaining)
	}
	expected := time.Unix(resetUnix, 0)
	if !rl.Reset.Equal(expected) {
		t.Errorf("reset = %v, want %v", rl.Reset, expected)
	}
}

func TestRetry_5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error": "internal", "message": "try again"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status": "healthy"}`)
	}))
	defer srv.Close()

	client := verifip.NewClient("key",
		verifip.WithBaseURL(srv.URL),
		verifip.WithMaxRetries(3),
	)

	resp, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("status = %q, want %q", resp.Status, "healthy")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}
