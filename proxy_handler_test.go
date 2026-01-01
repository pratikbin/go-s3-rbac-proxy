package main

import (
	"regexp"
	"sync"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	hexPattern := regexp.MustCompile(`^[0-9a-f]{32}$`)

	tests := []struct {
		name        string
		iterations  int
		goroutines  int
		concurrent  bool
		checkFormat bool
		checkUnique bool
	}{
		{
			name:        "basic_generation",
			iterations:  1000,
			goroutines:  1,
			concurrent:  false,
			checkFormat: true,
			checkUnique: true,
		},
		{
			name:        "concurrent_uniqueness",
			iterations:  100,
			goroutines:  10,
			concurrent:  true,
			checkFormat: false,
			checkUnique: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.concurrent {
				// Concurrent generation test
				idsChan := make(chan string, tt.goroutines*tt.iterations)
				var wg sync.WaitGroup

				// Generate IDs concurrently
				for i := 0; i < tt.goroutines; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < tt.iterations; j++ {
							idsChan <- generateRequestID()
						}
					}()
				}

				// Wait for all goroutines
				wg.Wait()
				close(idsChan)

				// Check for duplicates
				ids := make(map[string]bool)
				count := 0
				for id := range idsChan {
					if tt.checkUnique && ids[id] {
						t.Errorf("Duplicate ID found in concurrent generation: %s", id)
					}
					ids[id] = true
					count++
				}

				expected := tt.goroutines * tt.iterations
				if count != expected {
					t.Errorf("Generated %d IDs, expected %d", count, expected)
				}

				t.Logf("✅ Generated %d unique IDs across %d concurrent goroutines", count, tt.goroutines)
			} else {
				// Sequential generation test
				ids := make(map[string]bool)

				for i := 0; i < tt.iterations; i++ {
					id := generateRequestID()

					// Check format
					if tt.checkFormat {
						if !hexPattern.MatchString(id) {
							t.Errorf("Request ID has invalid format: %s (expected 32 lowercase hex chars)", id)
						}
						if len(id) != 32 {
							t.Errorf("Request ID has wrong length: %d (expected 32)", len(id))
						}
					}

					// Check for duplicates
					if tt.checkUnique && ids[id] {
						t.Errorf("Duplicate request ID generated: %s", id)
					}
					ids[id] = true
				}

				t.Logf("✅ Generated %d unique request IDs", tt.iterations)
				t.Logf("✅ All IDs are 32-character lowercase hex strings")
			}
		})
	}
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
					if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
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
					if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
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
					if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
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
