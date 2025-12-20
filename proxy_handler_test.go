package main

import (
	"regexp"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	// Test that request IDs are properly formatted
	hexPattern := regexp.MustCompile(`^[0-9a-f]{32}$`)

	// Generate multiple IDs
	ids := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		id := generateRequestID()

		// Check format (32 character lowercase hex)
		if !hexPattern.MatchString(id) {
			t.Errorf("Request ID has invalid format: %s (expected 32 lowercase hex chars)", id)
		}

		// Check length
		if len(id) != 32 {
			t.Errorf("Request ID has wrong length: %d (expected 32)", len(id))
		}

		// Check for duplicates
		if ids[id] {
			t.Errorf("Duplicate request ID generated: %s", id)
		}
		ids[id] = true
	}

	t.Logf("✅ Generated %d unique request IDs", iterations)
	t.Logf("✅ All IDs are 32-character lowercase hex strings")
	t.Logf("✅ No collisions detected in %d iterations", iterations)
}

func TestGenerateRequestIDUniqueness(t *testing.T) {
	// Generate IDs concurrently to test for race conditions
	const goroutines = 10
	const idsPerGoroutine = 100

	idsChan := make(chan string, goroutines*idsPerGoroutine)
	done := make(chan bool, goroutines)

	// Generate IDs concurrently
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < idsPerGoroutine; j++ {
				idsChan <- generateRequestID()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}
	close(idsChan)

	// Check for duplicates
	ids := make(map[string]bool)
	count := 0
	for id := range idsChan {
		if ids[id] {
			t.Errorf("Duplicate ID found in concurrent generation: %s", id)
		}
		ids[id] = true
		count++
	}

	expected := goroutines * idsPerGoroutine
	if count != expected {
		t.Errorf("Generated %d IDs, expected %d", count, expected)
	}

	t.Logf("✅ Generated %d unique IDs across %d concurrent goroutines", count, goroutines)
	t.Logf("✅ No collisions in high-concurrency scenario")
}

func TestGenerateRequestIDFormat(t *testing.T) {
	tests := []struct {
		name string
		test func(string) bool
	}{
		{
			name: "contains_only_hex_chars",
			test: func(id string) bool {
				for _, c := range id {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						return false
					}
				}
				return true
			},
		},
		{
			name: "no_uppercase_letters",
			test: func(id string) bool {
				for _, c := range id {
					if c >= 'A' && c <= 'Z' {
						return false
					}
				}
				return true
			},
		},
		{
			name: "no_special_characters",
			test: func(id string) bool {
				for _, c := range id {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						return false
					}
				}
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := generateRequestID()
			if !tt.test(id) {
				t.Errorf("Request ID failed test '%s': %s", tt.name, id)
			}
		})
	}
}
