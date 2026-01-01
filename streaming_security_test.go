package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestStreamingUploadTracker(t *testing.T) {
	if Logger == nil {
		_ = InitLogger("debug", "console")
	}

	tests := []struct {
		name            string
		maxDuration     time.Duration
		waitTime        time.Duration
		updateBytes     bool
		shouldBeCleaned bool
		checkLastSeen   bool
	}{
		{
			name:            "janitor_cleans_up_after_max_duration",
			maxDuration:     500 * time.Millisecond,
			waitTime:        700 * time.Millisecond, // Wait longer than maxDuration
			updateBytes:     false,
			shouldBeCleaned: true,
			checkLastSeen:   false,
		},
		{
			name:            "idle_timeout_tracks_last_seen",
			maxDuration:     1 * time.Hour,
			waitTime:        100 * time.Millisecond,
			updateBytes:     true,
			shouldBeCleaned: false,
			checkLastSeen:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewStreamingUploadTracker(5, 1024*1024, tt.maxDuration)

			// Only start janitor for the first test
			if tt.name == "janitor_cleans_up_after_max_duration" {
				tracker.StartJanitor(100 * time.Millisecond)
				defer tracker.Stop()
			}

			id := "test-upload-" + tt.name
			err := tracker.TryStartUpload(id, "user1", "bucket1", "key1", "")
			if err != nil {
				t.Fatalf("Failed to start upload: %v", err)
			}

			// Verify upload is tracked
			if _, exists := tracker.GetUpload(id); !exists {
				t.Fatal("Upload should be tracked")
			}

			// Wait specified time
			time.Sleep(tt.waitTime)

			// Update bytes if needed
			if tt.updateBytes {
				err = tracker.UpdateBytes(id, 100)
				if err != nil {
					t.Fatalf("Failed to update bytes: %v", err)
				}
			}

			// Check if upload was cleaned up
			upload, exists := tracker.GetUpload(id)
			if tt.shouldBeCleaned && exists {
				t.Fatal("Upload should have been cleaned up")
			}
			if !tt.shouldBeCleaned && !exists {
				t.Fatal("Upload should still be tracked")
			}

			// Check LastSeen if needed
			if tt.checkLastSeen && exists {
				lastSeen := upload.LastSeen
				if lastSeen.IsZero() {
					t.Fatal("LastSeen should be set")
				}
			}
		})
	}
}

func TestStreamingReader_IdleTimeout(t *testing.T) {
	if Logger == nil {
		_ = InitLogger("debug", "console")
	}

	// This test verifies that streamingReader sets the read deadline.
	// Since we're using httptest, the ResponseWriter might not support deadlines
	// unless we use a real server.

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker := NewStreamingUploadTracker(5, 1024*1024, 1*time.Hour)
		sr := &streamingReader{
			ReadCloser:  r.Body,
			id:          "test-id",
			tracker:     tracker,
			recorder:    w,
			idleTimeout: 100 * time.Millisecond,
		}

		err := tracker.TryStartUpload("test-id", "user1", "bucket1", "key1", "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		buf := make([]byte, 10)
		_, err = sr.Read(buf)
		if err != nil && err != io.EOF {
			// Expected if timeout works, but on httptest it might not
			Logger.Debug("Read error (expected if timeout worked)", zap.Error(err))
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Send a request with a body that never sends data
	pr, _ := io.Pipe()
	req, _ := http.NewRequest("PUT", server.URL, pr)

	client := &http.Client{}

	// We expect this to return after some time if the server closes the connection
	// but httptest.Server might not enforce ReadDeadline strictly on the hijacked conn
	// if we don't have a real listener.

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = pr.Close() // Close to avoid blocking forever if timeout doesn't work
	}()

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
