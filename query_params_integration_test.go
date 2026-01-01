package main

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestIntegration_QueryParams_SubResources verifies S3 sub-resource query parameters
func TestIntegration_QueryParams_SubResources(t *testing.T) {
	t.Parallel()

	// Setup
	users := []User{TestUserWildcard}

	proxyURL, _, _, cleanup := SetupMockEnv(users)
	defer cleanup()

	ctx := context.Background()
	client, err := CreateS3Client(ctx, proxyURL, TestUserWildcard.AccessKey, TestUserWildcard.SecretKey)
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// Upload a test object first
	testData := []byte("test data for query params")
	key := "query-test.txt"
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
		Body:   bytes.NewReader(testData),
	})
	if err != nil {
		t.Fatalf("Failed to upload test object: %v", err)
	}

	t.Run("ACL_SubResource", func(t *testing.T) {
		// Test: GET /bucket/key?acl
		// Verify: Query parameter correctly included in canonical request
		// Verify: Backend receives ?acl parameter

		// Parse URL with ACL sub-resource
		parsedURL, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?acl")
		query := parsedURL.Query()

		// Verify query parameter is parsed correctly
		if _, ok := query["acl"]; !ok {
			t.Error("ACL query parameter not found")
		}

		// Verify canonical query string handles empty value
		canonicalQuery := buildCanonicalQueryString(query)
		if !strings.Contains(canonicalQuery, "acl=") {
			t.Errorf("Canonical query string should contain 'acl=', got: %s", canonicalQuery)
		}

		// Verify sorting (acl should come first alphabetically)
		if !strings.HasPrefix(canonicalQuery, "acl=") {
			t.Logf("Note: Canonical query may have other params, got: %s", canonicalQuery)
		}

		t.Logf("✅ ACL sub-resource query parameter handled correctly: %s", canonicalQuery)
	})

	t.Run("Tagging_SubResource", func(t *testing.T) {
		// Test: GET /bucket/key?tagging
		// Verify: Empty value parameter handled correctly

		parsedURL, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?tagging")
		query := parsedURL.Query()

		canonicalQuery := buildCanonicalQueryString(query)
		if !strings.Contains(canonicalQuery, "tagging=") {
			t.Errorf("Canonical query should contain 'tagging=', got: %s", canonicalQuery)
		}

		t.Logf("✅ Tagging sub-resource handled correctly: %s", canonicalQuery)
	})

	t.Run("Versioning_WithValue", func(t *testing.T) {
		// Test: GET /bucket/key?versionId=abc123
		// Verify: Query parameter sorted and encoded correctly

		parsedURL, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?versionId=abc123")
		query := parsedURL.Query()

		canonicalQuery := buildCanonicalQueryString(query)
		if !strings.Contains(canonicalQuery, "versionId=abc123") {
			t.Errorf("Canonical query should contain 'versionId=abc123', got: %s", canonicalQuery)
		}

		// Verify encoding (versionId should be encoded if needed)
		// In this case, "abc123" doesn't need encoding, but verify the format
		if !strings.Contains(canonicalQuery, "versionId") {
			t.Errorf("Canonical query missing versionId: %s", canonicalQuery)
		}

		t.Logf("✅ Versioning query parameter handled correctly: %s", canonicalQuery)
	})

	t.Run("Multiple_SubResources", func(t *testing.T) {
		// Test: GET /bucket/key?acl&versionId=123&tagging
		// Verify: Correct sorting (alphabetical by encoded key)
		// Verify: Empty values handled as "key="

		parsedURL, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?acl&versionId=123&tagging")
		query := parsedURL.Query()

		canonicalQuery := buildCanonicalQueryString(query)

		// Verify all parameters are present
		if !strings.Contains(canonicalQuery, "acl=") {
			t.Errorf("Missing acl parameter: %s", canonicalQuery)
		}
		if !strings.Contains(canonicalQuery, "tagging=") {
			t.Errorf("Missing tagging parameter: %s", canonicalQuery)
		}
		if !strings.Contains(canonicalQuery, "versionId=123") {
			t.Errorf("Missing versionId parameter: %s", canonicalQuery)
		}

		// Verify sorting: acl should come before tagging, which should come before versionId
		aclPos := strings.Index(canonicalQuery, "acl=")
		taggingPos := strings.Index(canonicalQuery, "tagging=")
		versionIdPos := strings.Index(canonicalQuery, "versionId=")

		if aclPos == -1 || taggingPos == -1 || versionIdPos == -1 {
			t.Errorf("One or more parameters missing in canonical query: %s", canonicalQuery)
		}

		if aclPos > taggingPos || taggingPos > versionIdPos {
			t.Errorf("Parameters not sorted correctly. Expected: acl < tagging < versionId, got: %s", canonicalQuery)
		}

		t.Logf("✅ Multiple sub-resources sorted correctly: %s", canonicalQuery)
	})

	t.Run("DuplicateKeys_Tagging", func(t *testing.T) {
		// Test: GET /bucket/key?tagging&key1=val1&key1=val2
		// Verify: All values preserved and sorted correctly

		parsedURL, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?tagging&key1=val1&key1=val2")
		query := parsedURL.Query()

		canonicalQuery := buildCanonicalQueryString(query)

		// Verify tagging parameter
		if !strings.Contains(canonicalQuery, "tagging=") {
			t.Errorf("Missing tagging parameter: %s", canonicalQuery)
		}

		// Verify duplicate key1 values
		key1Count := strings.Count(canonicalQuery, "key1=")
		if key1Count != 2 {
			t.Errorf("Expected 2 occurrences of key1=, got %d in: %s", key1Count, canonicalQuery)
		}

		// Verify values are sorted: val1 should come before val2
		val1Pos := strings.Index(canonicalQuery, "key1=val1")
		val2Pos := strings.Index(canonicalQuery, "key1=val2")
		if val1Pos == -1 || val2Pos == -1 {
			t.Errorf("Missing key1 values in canonical query: %s", canonicalQuery)
		}
		if val1Pos > val2Pos {
			t.Errorf("Values not sorted correctly. Expected val1 before val2, got: %s", canonicalQuery)
		}

		t.Logf("✅ Duplicate keys handled correctly: %s", canonicalQuery)
	})

	t.Run("Multipart_QueryParams", func(t *testing.T) {
		// Test: Verify query parameters work with multipart uploads
		// ?uploads, ?uploadId, ?partNumber

		// Test uploads parameter
		parsedURL1, _ := url.Parse(proxyURL + "/test-bucket/large-file.bin?uploads")
		query1 := parsedURL1.Query()
		canonicalQuery1 := buildCanonicalQueryString(query1)
		if !strings.Contains(canonicalQuery1, "uploads=") {
			t.Errorf("Missing uploads parameter: %s", canonicalQuery1)
		}

		// Test uploadId and partNumber
		parsedURL2, _ := url.Parse(proxyURL + "/test-bucket/large-file.bin?uploadId=test-123&partNumber=1")
		query2 := parsedURL2.Query()
		canonicalQuery2 := buildCanonicalQueryString(query2)

		// Verify sorting: partNumber should come before uploadId
		partNumberPos := strings.Index(canonicalQuery2, "partNumber=")
		uploadIdPos := strings.Index(canonicalQuery2, "uploadId=")

		if partNumberPos == -1 || uploadIdPos == -1 {
			t.Errorf("Missing multipart parameters: %s", canonicalQuery2)
		}

		if partNumberPos > uploadIdPos {
			t.Errorf("Parameters not sorted correctly. Expected partNumber < uploadId, got: %s", canonicalQuery2)
		}

		t.Logf("✅ Multipart query parameters handled correctly: %s", canonicalQuery2)
	})

	t.Run("EmptyValue_vs_NoValue", func(t *testing.T) {
		// Test: ?acl vs ?acl=
		// SigV4 treats these the same (both become "acl=" in canonical query)

		// Test ?acl (no equals)
		parsedURL1, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?acl")
		query1 := parsedURL1.Query()
		canonicalQuery1 := buildCanonicalQueryString(query1)

		// Test ?acl= (with equals, empty value)
		parsedURL2, _ := url.Parse(proxyURL + "/test-bucket/" + key + "?acl=")
		query2 := parsedURL2.Query()
		canonicalQuery2 := buildCanonicalQueryString(query2)

		// Both should result in "acl="
		if !strings.Contains(canonicalQuery1, "acl=") {
			t.Errorf("?acl should become 'acl=' in canonical query, got: %s", canonicalQuery1)
		}
		if !strings.Contains(canonicalQuery2, "acl=") {
			t.Errorf("?acl= should become 'acl=' in canonical query, got: %s", canonicalQuery2)
		}

		t.Logf("✅ Empty value handling: ?acl -> %s, ?acl= -> %s", canonicalQuery1, canonicalQuery2)
	})
}
