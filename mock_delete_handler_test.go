package main

import (
	"encoding/xml"
	"io"
	"net/http"
)

// handleDeleteObjects handles the S3 DeleteObjects (Batch Delete) request
func (m *mockS3Backend) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	// Read body (should ensure it's XML, but we can just use the proxy's body validation)
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.lastBody = body
	m.mu.Unlock()

	// Response for successful deletion
	// For simplicity, we assume successful deletion of all objects
	// A real mock parsing the XML would be more complex, but this is enough to verify
	// that the proxy allows the request through and handles the body correctly.

	// Minimal response using proper XML marshaling
	result := DeleteResult{}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Write XML declaration and marshaled result
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Failed to encode XML response", http.StatusInternalServerError)
	}
}
