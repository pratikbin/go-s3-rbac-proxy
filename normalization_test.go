package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestS3EncodePath_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/bucket/obj", "/bucket/obj"},
		{"/bucket/file.txt", "/bucket/file.txt"},
		{"/bucket/file (1).txt", "/bucket/file%20%281%29.txt"},
		{"/bucket/test@#$.txt", "/bucket/test%40%23%24.txt"},
		{"/bucket/space here", "/bucket/space%20here"},
		{"//bucket//obj", "//bucket//obj"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := S3EncodePath(tt.input)
			if got != tt.expected {
				t.Errorf("S3EncodePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetCanonicalURI_Normalization_Extended(t *testing.T) {
	tests := []struct {
		name     string
		urlPath  string
		expected string
	}{
		{
			name:     "Simple",
			urlPath:  "/bucket/key",
			expected: "/bucket/key",
		},
		{
			name:     "With Spaces",
			urlPath:  "/bucket/folder/my file.txt",
			expected: "/bucket/folder/my%20file.txt",
		},
		{
			name:     "Trailing Slash",
			urlPath:  "/bucket/folder/",
			expected: "/bucket/folder/",
		},
		{
			name:     "Multiple Slashes Preserved if present",
			urlPath:  "/bucket//object",
			expected: "/bucket//object",
		},
		{
			name:     "DoubleSlashStart",
			urlPath:  "//bucket/object",
			expected: "//bucket/object",
		},
		{
			name:     "DotSegment_CurrentDir",
			urlPath:  "/bucket/./object",
			expected: "/bucket/./object",
		},
		{
			name:     "DotSegment_ParentDir",
			urlPath:  "/bucket/../otherbucket/object",
			expected: "/bucket/../otherbucket/object",
		},
		{
			name:     "MultipleSlashesInKey",
			urlPath:  "/bucket/folder//file.txt",
			expected: "/bucket/folder//file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Path: tt.urlPath}
			req := &http.Request{URL: u}
			got := getCanonicalURI(req)
			if got != tt.expected {
				t.Errorf("getCanonicalURI() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractBucket_Extended(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		path           string
		expectedBucket string
		description    string
	}{
		{
			name:           "StandardPathStyle",
			host:           "proxy.example.com",
			path:           "/bucket/key",
			expectedBucket: "bucket",
			description:    "Standard path-style format",
		},
		{
			name:           "RootPath",
			host:           "proxy.example.com",
			path:           "/",
			expectedBucket: "",
			description:    "Root path (ListBuckets)",
		},
		{
			name:           "OnlyBucket",
			host:           "proxy.example.com",
			path:           "/bucket",
			expectedBucket: "bucket",
			description:    "Path with only bucket name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			req.Host = tt.host

			bucket := extractBucket(req)
			if bucket != tt.expectedBucket {
				t.Errorf("extractBucket() with host=%q, path=%q = %q, want %q (%s)",
					tt.host, tt.path, bucket, tt.expectedBucket, tt.description)
			}
		})
	}
}

func TestExtractBucketFromPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedBucket string
	}{
		{"Standard", "/bucket/key", "bucket"},
		{"DoubleSlashStart", "//bucket/key", ""},
		{"TripleSlash", "///bucket/key", ""},
		{"EmptyPath", "", ""},
		{"RootPath", "/", ""},
		{"OnlyBucket", "/bucket", "bucket"},
		{"OnlyBucketTrailingSlash", "/bucket/", "bucket"},
		{"PathTraversal", "/bucket/../other/key", "bucket"},
		{"DotSegment", "/bucket/./key", "bucket"},
		{"MultipleSlashes", "/bucket//key", "bucket"},
		{"TrailingSlash", "/bucket/key/", "bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket := extractBucketFromPath(tt.path)
			if bucket != tt.expectedBucket {
				t.Errorf("extractBucketFromPath(%q) = %q, want %q", tt.path, bucket, tt.expectedBucket)
			}
		})
	}
}
