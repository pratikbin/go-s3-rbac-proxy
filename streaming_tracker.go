package main

import (
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// StreamingUpload tracks an active streaming/chunked upload
type StreamingUpload struct {
	UserAccessKey string
	Bucket        string
	Key           string
	StartTime     time.Time
	LastSeen      time.Time // Last time data was received
	BytesReceived int64
	UploadID      string // For multipart uploads
}

const numShards = 32

type uploadShard struct {
	mu      sync.RWMutex
	uploads map[string]*StreamingUpload
}

type userCountShard struct {
	mu     sync.Mutex
	counts map[string]int
}

// UploadTracker defines the interface for tracking streaming uploads
type UploadTracker interface {
	TryStartUpload(id, userAccessKey, bucket, key, uploadID string) error
	UpdateBytes(id string, bytes int64) error
	CompleteUpload(id string)
	GetUpload(id string) (*StreamingUpload, bool)
	Stop()
	StartJanitor(interval time.Duration)
}

// StreamingUploadTracker manages concurrent streaming uploads with limits
type StreamingUploadTracker struct {
	uploadShards    [numShards]*uploadShard
	userCountShards [numShards]*userCountShard
	maxConcurrent   int
	maxSize         int64
	maxDuration     time.Duration
	stopJanitor     chan struct{}
}

// NewStreamingUploadTracker creates a new tracker with security limits
func NewStreamingUploadTracker(maxConcurrent int, maxSize int64, maxDuration time.Duration) *StreamingUploadTracker {
	t := &StreamingUploadTracker{
		maxConcurrent: maxConcurrent,
		maxSize:       maxSize,
		maxDuration:   maxDuration,
		stopJanitor:   make(chan struct{}),
	}
	for i := 0; i < numShards; i++ {
		t.uploadShards[i] = &uploadShard{
			uploads: make(map[string]*StreamingUpload),
		}
		t.userCountShards[i] = &userCountShard{
			counts: make(map[string]int),
		}
	}
	return t
}

func (t *StreamingUploadTracker) getUploadShard(id string) *uploadShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return t.uploadShards[h.Sum32()%numShards]
}

func (t *StreamingUploadTracker) getUserShard(user string) *userCountShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(user))
	return t.userCountShards[h.Sum32()%numShards]
}

// StartJanitor runs a background goroutine to clean up stale uploads
func (t *StreamingUploadTracker) StartJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				t.cleanupStaleUploads()
			case <-t.stopJanitor:
				ticker.Stop()
				return
			}
		}
	}()
}

// Stop stops the janitor goroutine
func (t *StreamingUploadTracker) Stop() {
	close(t.stopJanitor)
}

func (t *StreamingUploadTracker) cleanupStaleUploads() {
	now := time.Now()
	// Idle timeout: if no data for 2 minutes, consider it a zombie
	idleTimeout := 2 * time.Minute

	for i := 0; i < numShards; i++ {
		shard := t.uploadShards[i]
		shard.mu.Lock()
		for id, upload := range shard.uploads {
			isStale := false
			var reason string

			// Check absolute duration
			if t.maxDuration > 0 && now.Sub(upload.StartTime) > t.maxDuration {
				isStale = true
				reason = "duration limit exceeded"
			} else if now.Sub(upload.LastSeen) > idleTimeout {
				// Check idle time
				isStale = true
				reason = "idle timeout exceeded"
			}

			if isStale {
				Logger.Warn("cleaning up stale streaming upload",
					zap.String("id", id),
					zap.String("user", upload.UserAccessKey),
					zap.String("bucket", upload.Bucket),
					zap.String("key", upload.Key),
					zap.String("reason", reason),
				)
				t.cleanupUploadLocked(shard, id)
			}
		}
		shard.mu.Unlock()
	}
}

// TryStartUpload attempts to start a new streaming upload with security checks
func (t *StreamingUploadTracker) TryStartUpload(id, userAccessKey, bucket, key, uploadID string) error {
	uShard := t.getUserShard(userAccessKey)
	upShard := t.getUploadShard(id)

	// To avoid deadlock, we must lock in consistent order: Upload shard then User shard
	upShard.mu.Lock()
	defer upShard.mu.Unlock()
	uShard.mu.Lock()
	defer uShard.mu.Unlock()

	// Check user concurrency limit
	if t.maxConcurrent > 0 {
		currentCount := uShard.counts[userAccessKey]
		if currentCount >= t.maxConcurrent {
			return fmt.Errorf("user %s has reached maximum concurrent streaming uploads (%d)", userAccessKey, t.maxConcurrent)
		}
	}

	// Create and register the upload
	now := time.Now()
	upload := &StreamingUpload{
		UserAccessKey: userAccessKey,
		Bucket:        bucket,
		Key:           key,
		StartTime:     now,
		LastSeen:      now,
		BytesReceived: 0,
		UploadID:      uploadID,
	}

	upShard.uploads[id] = upload
	uShard.counts[userAccessKey]++

	return nil
}

// UpdateBytes updates the byte count for an upload and checks size limits
func (t *StreamingUploadTracker) UpdateBytes(id string, bytes int64) error {
	shard := t.getUploadShard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	upload, exists := shard.uploads[id]
	if !exists {
		return fmt.Errorf("upload not found: %s", id)
	}

	now := time.Now()
	upload.BytesReceived += bytes
	upload.LastSeen = now

	// Check size limit
	if t.maxSize > 0 && upload.BytesReceived > t.maxSize {
		t.cleanupUploadLocked(shard, id)
		return fmt.Errorf("streaming upload exceeded maximum size (%d bytes)", t.maxSize)
	}

	// Check duration limit
	if t.maxDuration > 0 && now.Sub(upload.StartTime) > t.maxDuration {
		t.cleanupUploadLocked(shard, id)
		return fmt.Errorf("streaming upload exceeded maximum duration (%v)", t.maxDuration)
	}

	return nil
}

// CompleteUpload marks an upload as completed and cleans up resources
func (t *StreamingUploadTracker) CompleteUpload(id string) {
	shard := t.getUploadShard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	t.cleanupUploadLocked(shard, id)
}

// GetUpload returns a copy of the tracked upload if it exists.
// Useful for testing and monitoring.
func (t *StreamingUploadTracker) GetUpload(id string) (*StreamingUpload, bool) {
	shard := t.getUploadShard(id)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	upload, exists := shard.uploads[id]
	if !exists {
		return nil, false
	}
	// Return a copy to avoid race conditions
	uploadCopy := *upload
	return &uploadCopy, true
}

// cleanupUploadLocked removes an upload and updates user count.
// MUST be called with shard.mu held.
func (t *StreamingUploadTracker) cleanupUploadLocked(shard *uploadShard, id string) {
	upload, exists := shard.uploads[id]
	if !exists {
		return
	}

	uShard := t.getUserShard(upload.UserAccessKey)
	uShard.mu.Lock()
	defer uShard.mu.Unlock()

	if count, exists := uShard.counts[upload.UserAccessKey]; exists {
		if count <= 1 {
			delete(uShard.counts, upload.UserAccessKey)
		} else {
			uShard.counts[upload.UserAccessKey] = count - 1
		}
	}
	delete(shard.uploads, id)
}

type streamingReader struct {
	io.ReadCloser
	id              string
	tracker         UploadTracker
	recorder        http.ResponseWriter
	idleTimeout     time.Duration
	deadlineSupport bool
	supportChecked  bool
}

func (r *streamingReader) Read(p []byte) (int, error) {
	if r.idleTimeout > 0 && (!r.supportChecked || r.deadlineSupport) {
		// Set read deadline to catch idle connections
		rc := http.NewResponseController(r.recorder)
		if err := rc.SetReadDeadline(time.Now().Add(r.idleTimeout)); err != nil {
			if !r.supportChecked {
				r.deadlineSupport = false
				r.supportChecked = true
				// Log once as debug if not supported
				Logger.Debug("read deadline not supported by writer", zap.Error(err))
			}
		} else if !r.supportChecked {
			r.deadlineSupport = true
			r.supportChecked = true
		}
	}

	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		if updateErr := r.tracker.UpdateBytes(r.id, int64(n)); updateErr != nil {
			// If limits exceeded (size/duration), return error to terminate the upload
			return n, fmt.Errorf("failed to update upload bytes: %w", updateErr)
		}
	}
	return n, err //nolint:wrapcheck // standard io behavior
}

func (r *streamingReader) Close() error {
	r.tracker.CompleteUpload(r.id)
	return r.ReadCloser.Close() //nolint:wrapcheck
}
