package verifip

import "time"

// CheckResponse represents the result of an IP fraud check.
type CheckResponse struct {
	RequestID      string         `json:"request_id"`
	IP             string         `json:"ip"`
	FraudScore     float64        `json:"fraud_score"`
	IsProxy        bool           `json:"is_proxy"`
	IsVPN          bool           `json:"is_vpn"`
	IsTor          bool           `json:"is_tor"`
	IsDatacenter   bool           `json:"is_datacenter"`
	CountryCode    string         `json:"country_code"`
	CountryName    string         `json:"country_name"`
	Region         string         `json:"region"`
	City           string         `json:"city"`
	ISP            string         `json:"isp"`
	ASN            uint32         `json:"asn"`
	ConnectionType string         `json:"connection_type"`
	Hostname       string         `json:"hostname"`
	SignalBreakdown map[string]int `json:"signal_breakdown"`
	Error          string         `json:"error,omitempty"`
}

// BatchRequest represents a request to check multiple IPs at once.
type BatchRequest struct {
	IPs []string `json:"ips"`
}

// BatchResponse represents the result of a batch IP check.
type BatchResponse struct {
	Results []CheckResponse `json:"results"`
}

// HealthResponse represents the API health status.
type HealthResponse struct {
	Status       string `json:"status"`
	Version      string `json:"version"`
	DataLoadedAt string `json:"data_loaded_at"`
	Redis        string `json:"redis"`
	Postgres     string `json:"postgres"`
	UptimeSeconds int   `json:"uptime_seconds"`
}

// RateLimitInfo contains the current rate limit state.
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Reset     time.Time `json:"reset"`
}

// ErrorResponse represents an error returned by the API.
type ErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}
