package main

import (
	"net/http"
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

func TestGetCanonicalURI_Normalization(t *testing.T) {
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
