package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// S3 XML response structures
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type DeleteResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
}

type MockS3Response struct {
	XMLName xml.Name `xml:"MockS3Response"`
}

// mockS3Backend simulates an S3 backend for integration testing
type mockS3Backend struct {
	calls       atomic.Int32
	lastMethod  string
	lastPath    string
	lastBody    []byte
	lastHeaders http.Header
	storage     sync.Map // key (bucket/object) -> body
	uploads     sync.Map // uploadId -> parts map
	mu          sync.Mutex
}

// newMockS3Backend creates a new mock S3 backend
func newMockS3Backend() *mockS3Backend {
	return &mockS3Backend{
		lastHeaders: make(http.Header),
	}
}

// ServeHTTP handles HTTP requests to the mock backend
func (m *mockS3Backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls.Add(1)

	m.mu.Lock()
	m.lastMethod = r.Method
	m.lastPath = r.URL.Path

	// Clone headers for inspection
	m.lastHeaders = r.Header.Clone()

	// Read body if present
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		m.lastBody = bodyBytes
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	m.mu.Unlock()

	// Handle different S3 operations
	query := r.URL.Query()

	// CreateMultipartUpload
	if r.Method == "POST" && query.Get("uploads") != "" {
		m.handleCreateMultipartUpload(w, r)
		return
	}

	// UploadPart
	if r.Method == "PUT" && query.Get("uploadId") != "" && query.Get("partNumber") != "" {
		m.handleUploadPart(w, r)
		return
	}

	// CompleteMultipartUpload
	if r.Method == "POST" && query.Get("uploadId") != "" {
		m.handleCompleteMultipartUpload(w, r)
		return
	}

	// DeleteObjects (Batch Delete)
	if r.Method == "POST" && query.Has("delete") {
		m.handleDeleteObjects(w, r)
		return
	}

	// PutObject
	if r.Method == "PUT" {
		m.handlePutObject(w, r)
		return
	}

	// GetObject
	if r.Method == "GET" {
		m.handleGetObject(w, r)
		return
	}

	// Default response
	w.Header().Set("ETag", `"mock-etag"`)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Write XML declaration and marshaled result
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	if err := xml.NewEncoder(w).Encode(MockS3Response{}); err != nil {
		http.Error(w, "Failed to encode XML response", http.StatusInternalServerError)
	}
}

func (m *mockS3Backend) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	uploadID := fmt.Sprintf("test-upload-%d", time.Now().UnixNano())

	// Store upload metadata
	m.uploads.Store(uploadID, &sync.Map{})

	// Extract key from path (remove bucket prefix)
	key := strings.TrimPrefix(r.URL.Path, "/test-bucket/")

	// Create XML response using proper marshaling
	result := InitiateMultipartUploadResult{
		Bucket:   "test-bucket",
		Key:      key,
		UploadId: uploadID,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Write XML declaration and marshaled result
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Failed to encode XML response", http.StatusInternalServerError)
	}
}

func (m *mockS3Backend) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")
	partNumber := r.URL.Query().Get("partNumber")

	// Read part body
	body, _ := io.ReadAll(r.Body)

	// Store part
	if partsVal, ok := m.uploads.Load(uploadID); ok {
		parts := partsVal.(*sync.Map)
		parts.Store(partNumber, body)
	}

	// Generate ETag from part content
	hash := sha256.Sum256(body)
	etag := fmt.Sprintf(`"part%s-%s"`, partNumber, hex.EncodeToString(hash[:8]))

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (m *mockS3Backend) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")

	// Read the XML body with part list
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.lastBody = body
	m.mu.Unlock()

	// Combine all parts
	var combinedBody bytes.Buffer
	if partsVal, ok := m.uploads.Load(uploadID); ok {
		parts := partsVal.(*sync.Map)
		// Simple iteration (parts should be combined in order in real implementation)
		parts.Range(func(key, value interface{}) bool {
			combinedBody.Write(value.([]byte))
			return true
		})
	}

	// Store combined object
	m.storage.Store(r.URL.Path, combinedBody.Bytes())

	// Extract key from path
	key := strings.TrimPrefix(r.URL.Path, "/test-bucket/")

	// Create XML response using proper marshaling
	result := CompleteMultipartUploadResult{
		Location: fmt.Sprintf("http://test-bucket.s3.amazonaws.com/%s", key),
		Bucket:   "test-bucket",
		Key:      key,
		ETag:     `"multipart-complete-etag"`,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Write XML declaration and marshaled result
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Failed to encode XML response", http.StatusInternalServerError)
	}
}

func (m *mockS3Backend) handlePutObject(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, _ := io.ReadAll(r.Body)

	// Store object
	m.storage.Store(r.URL.Path, body)

	// Generate ETag
	hash := sha256.Sum256(body)
	etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (m *mockS3Backend) handleGetObject(w http.ResponseWriter, r *http.Request) {
	// Retrieve stored object
	if bodyVal, ok := m.storage.Load(r.URL.Path); ok {
		body := bodyVal.([]byte)

		// Check for Range header
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			// Basic parsing for bytes=start-end
			if strings.HasPrefix(rangeHeader, "bytes=") {
				rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
				parts := strings.Split(rangeSpec, "-")
				if len(parts) == 2 {
					var start, end int
					_, _ = fmt.Sscanf(parts[0], "%d", &start)
					if parts[1] != "" {
						_, _ = fmt.Sscanf(parts[1], "%d", &end)
					} else {
						end = len(body) - 1
					}

					// Bounds check
					if start < 0 {
						start = 0
					}
					if end >= len(body) {
						end = len(body) - 1
					}
					if start <= end {
						// Return partial content
						partialBody := body[start : end+1]

						// S3 keeps original ETag for the object.
						fullHash := sha256.Sum256(body)
						etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(fullHash[:]))

						w.Header().Set("ETag", etag)
						w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
						w.Header().Set("Content-Length", fmt.Sprintf("%d", len(partialBody)))
						w.WriteHeader(http.StatusPartialContent)
						_, _ = w.Write(partialBody)
						return
					}
				}
			}
		}

		// Generate ETag
		hash := sha256.Sum256(body)
		etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))

		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// Object not found
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
	<Code>NoSuchKey</Code>
	<Message>The specified key does not exist.</Message>
</Error>`))
}

func (m *mockS3Backend) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.lastBody = body
	m.mu.Unlock()

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

func (m *mockS3Backend) GetCalls() int32 {
	return m.calls.Load()
}

func (m *mockS3Backend) GetLastMethod() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastMethod
}

func (m *mockS3Backend) GetLastPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastPath
}

func (m *mockS3Backend) GetLastHeaders() http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastHeaders.Clone()
}

func (m *mockS3Backend) GetLastBody() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.lastBody...)
}
