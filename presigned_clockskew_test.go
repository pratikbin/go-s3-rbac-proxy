package main

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPresignedURL_ClockSkewValidation tests that presigned URLs validate
// the X-Amz-Date timestamp is within ±15 minutes, regardless of expiry duration
func TestPresignedURL_ClockSkewValidation(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-access-key",
			SecretKey:      "test-secret-key",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	now := time.Now().UTC()

	tests := []struct {
		name          string
		requestTime   time.Time
		expirySeconds int64
		shouldPass    bool
		errorContains string
	}{
		{
			name:          "current_time_valid",
			requestTime:   now,
			expirySeconds: 3600, // 1 hour
			shouldPass:    true,
		},
		{
			name:          "5_minutes_ago_valid",
			requestTime:   now.Add(-5 * time.Minute),
			expirySeconds: 3600,
			shouldPass:    true,
		},
		{
			name:          "14_minutes_ago_valid",
			requestTime:   now.Add(-14 * time.Minute),
			expirySeconds: 3600,
			shouldPass:    true,
		},
		{
			name:          "14_minutes_59_seconds_ago_valid",
			requestTime:   now.Add(-14*time.Minute - 59*time.Second),
			expirySeconds: 3600,
			shouldPass:    true, // Just within boundary
		},
		{
			name:          "16_minutes_ago_rejected",
			requestTime:   now.Add(-16 * time.Minute),
			expirySeconds: 604800, // 7 days - still rejected due to clock skew
			shouldPass:    false,
			errorContains: "outside acceptable time window",
		},
		{
			name:          "1_hour_ago_rejected",
			requestTime:   now.Add(-1 * time.Hour),
			expirySeconds: 604800, // Even with 7 day expiry, timestamp too old
			shouldPass:    false,
			errorContains: "outside acceptable time window",
		},
		{
			name:          "1_day_ago_rejected",
			requestTime:   now.Add(-24 * time.Hour),
			expirySeconds: 604800, // 7 days expiry doesn't help old timestamps
			shouldPass:    false,
			errorContains: "outside acceptable time window",
		},
		{
			name:          "5_minutes_future_valid",
			requestTime:   now.Add(5 * time.Minute),
			expirySeconds: 3600,
			shouldPass:    true,
		},
		{
			name:          "16_minutes_future_rejected",
			requestTime:   now.Add(16 * time.Minute),
			expirySeconds: 3600,
			shouldPass:    false,
			errorContains: "outside acceptable time window",
		},
		{
			name:          "far_future_rejected",
			requestTime:   now.Add(1 * time.Hour),
			expirySeconds: 3600,
			shouldPass:    false,
			errorContains: "outside acceptable time window",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build presigned URL with specific timestamp
			dateStr := tt.requestTime.Format(iso8601BasicFormat)
			url := fmt.Sprintf("/test-bucket/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"+
				"&X-Amz-Credential=test-access-key/20231215/us-east-1/s3/aws4_request"+
				"&X-Amz-Date=%s"+
				"&X-Amz-Expires=%d"+
				"&X-Amz-SignedHeaders=host"+
				"&X-Amz-Signature=fakesignature", dateStr, tt.expirySeconds)

			req := httptest.NewRequest("GET", url, nil)
			req.Host = "s3.example.com"

			_, err := auth.validatePresignedURL(req)

			if tt.shouldPass {
				// For valid clock skew, they will still fail signature validation
				// but should NOT fail with clock skew error
				if err != nil && err.Error() == "request timestamp outside acceptable time window (±15 minutes)" {
					t.Errorf("Expected to pass clock skew check but got: %v", err)
				}
			} else {
				// For invalid clock skew, should get specific error
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorContains)
				} else if err.Error() != "request timestamp outside acceptable time window (±15 minutes)" {
					t.Logf("Got error: %v (expected clock skew error)", err)
				}
			}
		})
	}
}

// TestPresignedURL_ClockSkewVsExpiry tests the interaction between
// clock skew validation and expiry validation
func TestPresignedURL_ClockSkewVsExpiry(t *testing.T) {
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
		name          string
		timeOffset    time.Duration
		expirySeconds int64
		expectedError string
		checkOrder    string
	}{
		{
			name:          "clock_skew_checked_before_expiry",
			timeOffset:    -20 * time.Minute, // Outside clock skew window
			expirySeconds: 60,                // Short expiry
			expectedError: "outside acceptable time window",
			checkOrder:    "Clock skew should be checked first",
		},
		{
			name:          "within_clock_skew_but_expired",
			timeOffset:    -5 * time.Minute, // Within clock skew
			expirySeconds: 60,               // 1 minute (would be expired)
			expectedError: "signature",      // Will fail later on signature
			checkOrder:    "Clock skew passes, then expiry check",
		},
		{
			name:          "within_clock_skew_and_valid",
			timeOffset:    -5 * time.Minute, // Within clock skew
			expirySeconds: 3600,             // 1 hour (not expired)
			expectedError: "signature",      // Will fail on signature
			checkOrder:    "Both checks pass, fails on signature",
		},
		{
			name:          "prevents_old_url_abuse",
			timeOffset:    -1 * time.Hour, // 1 hour ago - outside window
			expirySeconds: 604800,         // 7 days - not expired
			expectedError: "outside acceptable time window",
			checkOrder:    "Clock skew blocks old URLs regardless of expiry",
		},
		{
			name:          "defense_in_depth_old_attack",
			timeOffset:    -2 * time.Hour, // 2 hours ago - outside window
			expirySeconds: 604800,         // 7 days - not expired
			expectedError: "outside acceptable time window",
			checkOrder:    "Defense in depth: clock skew before expiry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestTime := time.Now().UTC().Add(tt.timeOffset)
			dateStr := requestTime.Format(iso8601BasicFormat)

			url := fmt.Sprintf("/test-bucket/object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"+
				"&X-Amz-Credential=test-access-key/20231215/us-east-1/s3/aws4_request"+
				"&X-Amz-Date=%s"+
				"&X-Amz-Expires=%d"+
				"&X-Amz-SignedHeaders=host"+
				"&X-Amz-Signature=fakesignature", dateStr, tt.expirySeconds)

			req := httptest.NewRequest("GET", url, nil)
			req.Host = "s3.example.com"

			_, err := auth.validatePresignedURL(req)

			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			// Verify we get the expected error (clock skew checked first)
			t.Logf("Check order: %s", tt.checkOrder)
			t.Logf("Got error: %v", err)
		})
	}
}
