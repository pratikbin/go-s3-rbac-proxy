package main

import (
	"net/http"
	"testing"
)

// Test that extractBucketFromPath still works independently
func TestVerification_ExtractBucketFromPath_Works(t *testing.T) {
	path := "/bucket-b/key"
	bucket := extractBucketFromPath(path)
	if bucket != "bucket-b" {
		t.Errorf("Expected bucket-b, got %s", bucket)
	}
	t.Log("✅ Verified: extractBucketFromPath extraction works for path-style.")
}

// Test that extractBucket handles both styles
func TestVerification_ExtractBucket_HandlesBothStyles(t *testing.T) {
	// Test path-style
	req1, _ := http.NewRequest("GET", "http://proxy.com/bucket-b/key", nil)
	req1.Host = "proxy.com"
	bucket1 := extractBucket(req1)
	if bucket1 != "bucket-b" {
		t.Errorf("Path-style: Expected bucket-b, got %s", bucket1)
	}

	// Test virtual-host style
	req2, _ := http.NewRequest("GET", "http://bucket-b.proxy.com/key", nil)
	req2.Host = "bucket-b.proxy.com"
	bucket2 := extractBucket(req2)
	if bucket2 != "bucket-b" {
		t.Errorf("Virtual-host style: Expected bucket-b, got %s", bucket2)
	}

	t.Log("✅ Verified: extractBucket handles both path-style and virtual-host style.")
}
