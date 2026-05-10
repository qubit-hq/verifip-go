package verifip

import "time"

// CheckResponse represents the result of an IP fraud check.
type CheckResponse struct {
	RequestID      string         `json:"request_id"`
	IP             string         `json:"ip"`
	FraudScore     int            `json:"fraud_score"`
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

// EmailResponse represents the result of an email risk check.
type EmailResponse struct {
	RequestID       string         `json:"request_id"`
	Email           string         `json:"email"`
	RiskScore       int            `json:"risk_score"`
	ValidSyntax     bool           `json:"valid_syntax"`
	MXFound         bool           `json:"mx_found"`
	IsDisposable    bool           `json:"is_disposable"`
	IsFreeProvider  bool           `json:"is_free_provider"`
	IsRoleBased     bool           `json:"is_role_based"`
	DomainAgeDays   int            `json:"domain_age_days"`
	Domain          string         `json:"domain"`
	SignalBreakdown map[string]int `json:"signal_breakdown"`
	Error           string         `json:"error,omitempty"`
}

// PhoneResponse represents the result of a phone number risk check.
type PhoneResponse struct {
	RequestID       string         `json:"request_id"`
	Phone           string         `json:"phone"`
	RiskScore       int            `json:"risk_score"`
	Valid           bool           `json:"valid"`
	CountryCode     string         `json:"country_code"`
	Carrier         string         `json:"carrier"`
	LineType        string         `json:"line_type"`
	IsVoIP          bool           `json:"is_voip"`
	SignalBreakdown map[string]int `json:"signal_breakdown"`
	Error           string         `json:"error,omitempty"`
}

// URLResponse represents the result of a URL risk check.
type URLResponse struct {
	RequestID          string         `json:"request_id"`
	URL                string         `json:"url"`
	RiskScore          int            `json:"risk_score"`
	IsPhishing         bool           `json:"is_phishing"`
	IsMalware          bool           `json:"is_malware"`
	SafeBrowsingThreat string         `json:"safe_browsing_threat"`
	InPhishtank        bool           `json:"in_phishtank"`
	SpamhausDBL        bool           `json:"spamhaus_dbl"`
	DomainAgeDays      int            `json:"domain_age_days"`
	SSLValid           bool           `json:"ssl_valid"`
	SSLIssuer          string         `json:"ssl_issuer"`
	SignalBreakdown    map[string]int `json:"signal_breakdown"`
	Error              string         `json:"error,omitempty"`
}

// WHOISResponse represents the result of a WHOIS lookup.
type WHOISResponse struct {
	RequestID      string `json:"request_id"`
	IP             string `json:"ip"`
	NetworkCIDR    string `json:"network_cidr"`
	NetworkName    string `json:"network_name"`
	OrgName        string `json:"org_name"`
	AbuseContact   string `json:"abuse_contact"`
	RIR            string `json:"rir"`
	AllocationDate string `json:"allocation_date"`
	CountryCode    string `json:"country_code"`
	ASN            uint32 `json:"asn"`
	ASNOrg         string `json:"asn_org"`
}

// ReportRequest represents a fraud report submission.
type ReportRequest struct {
	IP       string `json:"ip"`
	IsFraud  bool   `json:"is_fraud"`
	Category string `json:"category,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// ReportResponse represents the result of a fraud report submission.
type ReportResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// AssessResponse represents the result of a multi-signal risk assessment.
type AssessResponse struct {
	RequestID   string         `json:"request_id"`
	OverallRisk int            `json:"overall_risk"`
	IP          *CheckResponse `json:"ip,omitempty"`
	Email       *EmailResponse `json:"email,omitempty"`
	Phone       *PhoneResponse `json:"phone,omitempty"`
	URL         *URLResponse   `json:"url,omitempty"`
}
