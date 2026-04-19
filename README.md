# VerifIP Go SDK

Official Go client for the [VerifIP](https://verifip.io) IP fraud-detection API. Detect proxies, VPNs, Tor exit nodes, and datacenter IPs in real time.

## Installation

```bash
go get github.com/qubit-hq/verifip-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    verifip "github.com/qubit-hq/verifip-go"
)

func main() {
    client := verifip.NewClient("your-api-key")

    resp, err := client.Check(context.Background(), "8.8.8.8")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Fraud score: %.1f\n", resp.FraudScore)
    fmt.Printf("VPN: %v, Proxy: %v, Tor: %v\n", resp.IsVPN, resp.IsProxy, resp.IsTor)
}
```

## Methods

### `Check(ctx, ip) (*CheckResponse, error)`

Check a single IP address for fraud signals.

### `CheckBatch(ctx, ips) (*BatchResponse, error)`

Check up to 100 IP addresses in a single request.

```go
resp, err := client.CheckBatch(ctx, []string{"1.1.1.1", "8.8.8.8"})
for _, r := range resp.Results {
    fmt.Printf("%s: %.1f\n", r.IP, r.FraudScore)
}
```

### `Health(ctx) (*HealthResponse, error)`

Check API health status. Does not require authentication.

### `RateLimit() *RateLimitInfo`

Returns the most recently observed rate limit state, or `nil` if no requests have been made yet.

## Error Handling

All API errors are returned as `*verifip.APIError` with status code, error code, and message.

```go
resp, err := client.Check(ctx, ip)
if err != nil {
    if verifip.IsAuthError(err) {
        // Invalid or missing API key (401)
    }
    if verifip.IsRateLimitError(err) {
        // Too many requests (429)
    }
    log.Fatal(err)
}
```

## Configuration

```go
client := verifip.NewClient("your-api-key",
    verifip.WithBaseURL("https://custom-api.example.com"),
    verifip.WithTimeout(10 * time.Second),
    verifip.WithHTTPClient(customHTTPClient),
    verifip.WithMaxRetries(5),
)
```

## Rate Limits

Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`) are automatically parsed from every response and accessible via `client.RateLimit()`.

The client automatically retries on 429 and 5xx responses with exponential backoff and jitter.

## Requirements

- Go 1.22+
- Zero external dependencies (stdlib only)
