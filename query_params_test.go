package main

import (
	"testing"
)

func TestBuildCanonicalQueryString(t *testing.T) {
	tests := []struct {
		name     string
		query    map[string][]string
		expected string
	}{
		{
			name:     "Empty",
			query:    map[string][]string{},
			expected: "",
		},
		{
			name: "Simple",
			query: map[string][]string{
				"foo": {"bar"},
			},
			expected: "foo=bar",
		},
		{
			name: "Multiple Keys Sorted",
			query: map[string][]string{
				"b": {"2"},
				"a": {"1"},
			},
			expected: "a=1&b=2",
		},
		{
			name: "Multiple Values Sorted",
			query: map[string][]string{
				"key": {"val2", "val1"},
			},
			expected: "key=val1&key=val2",
			// Note: url.Values sorts by key, but value order depends on how it was parsed or inserted.
			// `buildCanonicalQueryString` implementation:
			// for k, values := range query { ... }
			// sort.Strings(parts)
			// It builds "key=val" strings and then sorts the WHOLE list of "key=val" strings.
			// So "key=val1" comes before "key=val2".
		},
		{
			name: "Sub-resources (no value)",
			query: map[string][]string{
				"acl": {""},
			},
			expected: "acl=",
			// AWS SigV4 rule: if value is empty, append "=".
			// But if the parameter itself had no equals in the request (e.g. ?acl),
			// standard Go ParseQuery might treat it as empty value.
			// SigV4 Canonical Query String requires "key=value". If value is empty, "key=".
		},
		{
			name: "Mixed Empty and Non-Empty",
			query: map[string][]string{
				"acl":       {""},
				"versionId": {"123"},
			},
			expected: "acl=&versionId=123",
		},
		{
			name: "Duplicate Keys with different values",
			query: map[string][]string{
				"tagging": {""},
				"key":     {"val2", "val1"},
			},
			expected: "key=val1&key=val2&tagging=",
		},
		{
			name: "Encoding Special Characters",
			query: map[string][]string{
				"email": {"user@example.com"},
				"path":  {"/foo/bar"},
			},
			// @ -> %40, / -> %2F (in query)
			// uriEncode function:
			// if (c >= 'A' && c <= 'Z') ... c == '.' || c == '~'
			// It does NOT include '/'.
			// So '/' should be encoded.
			expected: "email=user%40example.com&path=%2Ffoo%2Fbar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCanonicalQueryString(tt.query)
			if got != tt.expected {
				t.Errorf("buildCanonicalQueryString() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestUriEncode_QueryParamContext(t *testing.T) {
	// Verify specific query param encoding rules (RFC 3986)
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "user%40example.com"},
		{"foo/bar", "foo%2Fbar"}, // Slahses in query params MUST be encoded
		{"foo bar", "foo%20bar"},
		{"~", "~"}, // Tilde is unreserved
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := uriEncode(tt.input)
			if got != tt.expected {
				t.Errorf("uriEncode(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
