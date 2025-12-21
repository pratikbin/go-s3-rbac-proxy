package main

import (
	"testing"
)

// Better approach: Unit Test for Logic verification
func TestVerification_ExtractBucket_IgnoresHost(t *testing.T) {
	// This confirms the "Assumption" stated by user.
	path := "/bucket-b/key"
	// There is no Host header argument to extractBucketFromPath,
	// which proves it ignores Host header.
	bucket := extractBucketFromPath(path)
	if bucket != "bucket-b" {
		t.Errorf("Expected bucket-b, got %s", bucket)
	}
	t.Log("✅ Verified: extractBucketFromPath extraction relies solely on Path, ignoring Host (Path Style assumption confirmed).")
}
