package main

import (
	"context"
	"fmt"
	"log"
	"os"

	verifip "github.com/qubit-hq/verifip-go"
)

func main() {
	apiKey := os.Getenv("VERIFIP_API_KEY")
	if apiKey == "" {
		log.Fatal("VERIFIP_API_KEY environment variable is required")
	}

	client := verifip.NewClient(apiKey)

	// Check API health.
	health, err := client.Health(context.Background())
	if err != nil {
		log.Fatalf("health check failed: %v", err)
	}
	fmt.Printf("API status: %s (v%s)\n", health.Status, health.Version)

	// Check a single IP.
	resp, err := client.Check(context.Background(), "8.8.8.8")
	if err != nil {
		if verifip.IsAuthError(err) {
			log.Fatal("invalid API key")
		}
		if verifip.IsRateLimitError(err) {
			log.Fatal("rate limited — try again later")
		}
		log.Fatalf("check failed: %v", err)
	}

	fmt.Printf("IP:          %s\n", resp.IP)
	fmt.Printf("Fraud Score: %d\n", resp.FraudScore)
	fmt.Printf("VPN:         %v\n", resp.IsVPN)
	fmt.Printf("Proxy:       %v\n", resp.IsProxy)
	fmt.Printf("Tor:         %v\n", resp.IsTor)
	fmt.Printf("Datacenter:  %v\n", resp.IsDatacenter)
	fmt.Printf("Country:     %s (%s)\n", resp.CountryName, resp.CountryCode)
	fmt.Printf("ISP:         %s (ASN %d)\n", resp.ISP, resp.ASN)

	// Check current rate limit.
	if rl := client.RateLimit(); rl != nil {
		fmt.Printf("\nRate limit: %d/%d remaining, resets at %s\n",
			rl.Remaining, rl.Limit, rl.Reset.Format("15:04:05"))
	}
}
