// Package verifip provides a Go client for the VerifIP fraud-detection API.
//
// VerifIP detects proxies, VPNs, Tor exit nodes, and datacenter IPs in
// real time. This SDK wraps the REST API with automatic retries,
// rate-limit tracking, and idiomatic Go error handling.
//
// Usage:
//
//	client := verifip.NewClient("your-api-key")
//	resp, err := client.Check(context.Background(), "8.8.8.8")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Fraud score: %.1f\n", resp.FraudScore)
package verifip
