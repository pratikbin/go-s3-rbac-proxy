package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyHandler_ErrorHandler(t *testing.T) {
	// Setup minimal required objects
	users := []User{}
	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{}
	secConfig := SecurityConfig{}
	proxy := NewProxyHandler(auth, masterCreds, secConfig)

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "Context Canceled",
			err:            context.Canceled,
			expectedStatus: 0, // Should not write response
			expectedCode:   "",
		},
		{
			name:           "Timeout",
			err:            context.DeadlineExceeded,
			expectedStatus: http.StatusRequestTimeout,
			expectedCode:   "RequestTimeout",
		},
		{
			name:           "Incomplete Body (EOF)",
			err:            io.EOF,
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "IncompleteBody",
		},
		{
			name:           "Generic Error",
			err:            io.ErrUnexpectedEOF,
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "InternalError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/bucket/key", nil)

			// Call errorHandler directly
			proxy.errorHandler(rec, req, tt.err)

			if tt.expectedStatus == 0 {
				// Verify nothing was written
				if rec.Code != 200 { // Default new recorder code
					t.Errorf("Expected no response, got status %d", rec.Code)
				}
				if rec.Body.Len() > 0 {
					t.Errorf("Expected empty body, got %s", rec.Body.String())
				}
			} else {
				if rec.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
				}

				body := rec.Body.String()
				if !strings.Contains(body, "<Code>"+tt.expectedCode+"</Code>") {
					t.Errorf("Expected error code %s, got body: %s", tt.expectedCode, body)
				}
			}
		})
	}
}

func TestBufferPool_EdgeCases(t *testing.T) {
	pool := NewBufferPool()

	// Get a buffer
	buf := pool.Get()
	if len(buf) != optimalBufferSize {
		t.Errorf("Expected buffer len %d, got %d", optimalBufferSize, len(buf))
	}
	if cap(buf) != optimalBufferSize {
		t.Errorf("Expected buffer cap %d, got %d", optimalBufferSize, cap(buf))
	}

	// Put it back
	pool.Put(buf)

	// Test Put with wrong size (should be ignored)
	wrongSizeBuf := make([]byte, 1024)
	pool.Put(wrongSizeBuf)
	// No easy way to verify internal state without exposing verify methods,
	// but this exercises the code path (line 87: if cap(buf) != optimalBufferSize)

	// Test that we can still get a valid buffer after bad put
	buf2 := pool.Get()
	if len(buf2) != optimalBufferSize {
		t.Errorf("Expected buffer len %d, got %d", optimalBufferSize, len(buf2))
	}
	pool.Put(buf2)
}
