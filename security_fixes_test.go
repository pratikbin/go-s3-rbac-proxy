package main

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestPresignedURL_DoubleSigning tests the double signing vulnerability fix
func TestPresignedURL_DoubleSigning(t *testing.T) {
	// Create test user
	users := []User{
		{
			AccessKey:      "test-access-key",
			SecretKey:      "test-secret-key",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	tests := []struct {
		name         string
		queryDate    string
		headerDate   string
		shouldPass   bool
		errorMessage string
	}{
		{
			name:       "no_header_date_should_pass",
			queryDate:  "20231215T120000Z",
			headerDate: "",
			shouldPass: true,
		},
		{
			name:       "matching_dates_should_pass",
			queryDate:  "20231215T120000Z",
			headerDate: "20231215T120000Z",
			shouldPass: true,
		},
		{
			name:         "mismatched_dates_should_fail",
			queryDate:    "20231215T120000Z",
			headerDate:   "20231215T130000Z",
			shouldPass:   false,
			errorMessage: "X-Amz-Date mismatch",
		},
		{
			name:         "different_day_should_fail",
			queryDate:    "20231215T120000Z",
			headerDate:   "20231216T120000Z",
			shouldPass:   false,
			errorMessage: "X-Amz-Date mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build presigned URL query parameters
			// Note: This is a simplified test - actual signature validation will fail
			// but we're testing the double-signing check comes first
			req := httptest.NewRequest("GET", "/test-bucket/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test-access-key/20231215/us-east-1/s3/aws4_request&X-Amz-Date="+tt.queryDate+"&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=fakesignature", nil)
			req.Host = "s3.example.com"

			// Set header date if specified
			if tt.headerDate != "" {
				req.Header.Set("X-Amz-Date", tt.headerDate)
			}

			// Call validatePresignedURL
			_, err := auth.validatePresignedURL(req)

			if tt.shouldPass {
				// For tests that should pass the double-signing check,
				// they will still fail signature validation (which is expected)
				// We just need to ensure the error is NOT about date mismatch
				if err != nil && err.Error() == "X-Amz-Date mismatch between header and query parameter" {
					t.Errorf("Expected to pass double-signing check but got mismatch error")
				}
			} else {
				// For tests that should fail, verify we get the expected error
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMessage)
				} else if err.Error() != "X-Amz-Date mismatch between header and query parameter" {
					t.Errorf("Expected error '%s', got: %v", tt.errorMessage, err)
				}
			}
		})
	}
}

// TestSigningKeyCache tests that the signing key is cached correctly
func TestSigningKeyCache(t *testing.T) {
	signer := NewBackendSigner("test-access", "test-secret", "us-east-1")

	dateStamp := "20231215"
	stringToSign := "test-string-to-sign"

	// First call - should derive the key
	sig1 := signer.calculateSignature(dateStamp, stringToSign)

	// Verify key was cached
	signer.mu.RLock()
	if signer.cachedDateStamp != dateStamp {
		t.Errorf("Expected cached date stamp %s, got %s", dateStamp, signer.cachedDateStamp)
	}
	if signer.cachedSigningKey == nil {
		t.Error("Expected signing key to be cached")
	}
	signer.mu.RUnlock()

	// Second call with same date - should use cached key
	sig2 := signer.calculateSignature(dateStamp, stringToSign)

	// Signatures should be identical
	if sig1 != sig2 {
		t.Errorf("Signatures should match: %s != %s", sig1, sig2)
	}

	// Third call with different date - should derive new key
	newDateStamp := "20231216"
	sig3 := signer.calculateSignature(newDateStamp, stringToSign)

	// Verify new key was cached
	signer.mu.RLock()
	if signer.cachedDateStamp != newDateStamp {
		t.Errorf("Expected cached date stamp %s, got %s", newDateStamp, signer.cachedDateStamp)
	}
	signer.mu.RUnlock()

	// Signature should be different (different date)
	if sig1 == sig3 {
		t.Error("Signatures should differ for different dates")
	}

	// Fourth call with original date - should derive and cache again
	sig4 := signer.calculateSignature(dateStamp, stringToSign)

	// Should match first signature
	if sig1 != sig4 {
		t.Errorf("Signatures should match after re-caching: %s != %s", sig1, sig4)
	}
}

// TestSigningKeyCache_Concurrency tests thread safety of signing key cache
func TestSigningKeyCache_Concurrency(t *testing.T) {
	signer := NewBackendSigner("test-access", "test-secret", "us-east-1")

	dateStamp := "20231215"
	stringToSign := "test-string-to-sign"

	// Run 100 goroutines concurrently
	var wg sync.WaitGroup
	signatures := make([]string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			signatures[idx] = signer.calculateSignature(dateStamp, stringToSign)
		}(i)
	}

	wg.Wait()

	// All signatures should be identical
	firstSig := signatures[0]
	for i := 1; i < len(signatures); i++ {
		if signatures[i] != firstSig {
			t.Errorf("Signature %d doesn't match: %s != %s", i, signatures[i], firstSig)
		}
	}

	// Verify cache is consistent
	signer.mu.RLock()
	if signer.cachedDateStamp != dateStamp {
		t.Errorf("Expected cached date stamp %s, got %s", dateStamp, signer.cachedDateStamp)
	}
	if signer.cachedSigningKey == nil {
		t.Error("Expected signing key to be cached")
	}
	signer.mu.RUnlock()
}

// TestSigningKeyCache_DateRollover tests behavior across date boundaries
func TestSigningKeyCache_DateRollover(t *testing.T) {
	signer := NewBackendSigner("test-access", "test-secret", "us-east-1")

	stringToSign := "test-string-to-sign"

	// Simulate requests across multiple dates
	dates := []string{
		"20231215",
		"20231216",
		"20231217",
		"20231215", // Back to first date
		"20231216", // Back to second date
	}

	signatures := make(map[string]string)

	for _, dateStamp := range dates {
		sig := signer.calculateSignature(dateStamp, stringToSign)

		// First time seeing this date
		if existingSig, exists := signatures[dateStamp]; !exists {
			signatures[dateStamp] = sig
		} else {
			// Subsequent time - should match
			if sig != existingSig {
				t.Errorf("Signature for date %s doesn't match previous: %s != %s",
					dateStamp, sig, existingSig)
			}
		}
	}

	// Should have cached the last date
	signer.mu.RLock()
	lastDate := dates[len(dates)-1]
	if signer.cachedDateStamp != lastDate {
		t.Errorf("Expected cached date stamp %s, got %s", lastDate, signer.cachedDateStamp)
	}
	signer.mu.RUnlock()
}

// TestSigningKeyCache_Performance benchmarks the performance improvement
func BenchmarkSigningWithoutCache(b *testing.B) {
	// Create a new signer for each iteration to avoid caching
	dateStamp := "20231215"
	stringToSign := "test-string-to-sign"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer := NewBackendSigner("test-access", "test-secret", "us-east-1")
		_ = signer.calculateSignature(dateStamp, stringToSign)
	}
}

func BenchmarkSigningWithCache(b *testing.B) {
	// Single signer reused to benefit from caching
	signer := NewBackendSigner("test-access", "test-secret", "us-east-1")
	dateStamp := "20231215"
	stringToSign := "test-string-to-sign"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.calculateSignature(dateStamp, stringToSign)
	}
}

// TestPresignedURL_ExpiryEdgeCases tests expiry validation edge cases
func TestPresignedURL_ExpiryEdgeCases(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-access-key",
			SecretKey:      "test-secret-key",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	// Use current time for realistic expiry testing
	now := time.Now().UTC()
	validDate := now.Add(-1 * time.Hour).Format(iso8601BasicFormat)
	expiredDate := now.Add(-2 * time.Hour).Format(iso8601BasicFormat)

	tests := []struct {
		name         string
		date         string
		expires      string
		shouldExpire bool
	}{
		{
			name:         "valid_not_expired",
			date:         validDate,
			expires:      "7200", // 2 hours
			shouldExpire: false,  // Should still have ~1 hour left
		},
		{
			name:         "expired",
			date:         expiredDate,
			expires:      "3600", // 1 hour
			shouldExpire: true,   // Expired 1 hour ago
		},
		{
			name:         "max_expiry",
			date:         validDate,
			expires:      "604800", // 7 days (max allowed)
			shouldExpire: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test-bucket/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
				"&X-Amz-Credential=test-access-key/20231215/us-east-1/s3/aws4_request" +
				"&X-Amz-Date=" + tt.date +
				"&X-Amz-Expires=" + tt.expires +
				"&X-Amz-SignedHeaders=host" +
				"&X-Amz-Signature=fakesignature"

			req := httptest.NewRequest("GET", url, nil)
			req.Host = "s3.example.com"

			_, err := auth.validatePresignedURL(req)

			if tt.shouldExpire {
				if err == nil || err.Error() != "presigned URL has expired" {
					t.Errorf("Expected expiry error, got: %v", err)
				}
			} else {
				// For non-expired URLs, they will fail signature validation
				// but should NOT fail with expiry error
				if err != nil && err.Error() == "presigned URL has expired" {
					t.Error("Should not have expired but got expiry error")
				}
			}
		})
	}
}
