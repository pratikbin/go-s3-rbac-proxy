package main

import (
	"testing"
)

// Benchmark uriEncode with various input patterns
func BenchmarkURIEncode_Simple(b *testing.B) {
	input := "simple-path.txt"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_WithSpaces(b *testing.B) {
	input := "path with spaces and special chars"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_ComplexPath(b *testing.B) {
	input := "/bucket/folder/file name (2023) [draft].pdf?version=1&tag=test"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_UnicodeUTF8(b *testing.B) {
	input := "文件名-测试-2023.txt"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_LongPath(b *testing.B) {
	// Simulate a long S3 object key with many special characters
	input := "/bucket/very/deep/folder/structure/with spaces/and-dashes/under_scores/file.name (copy 1) [version 2] {draft}.pdf"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_AllSpecialChars(b *testing.B) {
	// Worst case: every character needs encoding
	input := "!@#$%^&*()+={}[]|\\:;\"'<>?,/ "
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

func BenchmarkURIEncode_NoEncodingNeeded(b *testing.B) {
	// Best case: no encoding needed
	input := "simple.filename.txt"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uriEncode(input)
	}
}

// Test correctness of uriEncode
func TestURIEncode_Correctness(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple_alphanumeric",
			input:    "test123",
			expected: "test123",
		},
		{
			name:     "with_space",
			input:    "test file",
			expected: "test%20file",
		},
		{
			name:     "special_chars",
			input:    "file (1).txt",
			expected: "file%20%281%29.txt",
		},
		{
			name:     "unreserved_chars",
			input:    "file-name_2023.txt~",
			expected: "file-name_2023.txt~",
		},
		{
			name:     "forward_slash",
			input:    "/bucket/object",
			expected: "%2Fbucket%2Fobject",
		},
		{
			name:     "percent_sign",
			input:    "100%",
			expected: "100%25",
		},
		{
			name:     "ampersand",
			input:    "tag1&tag2",
			expected: "tag1%26tag2",
		},
		{
			name:     "plus_sign",
			input:    "1+1=2",
			expected: "1%2B1%3D2",
		},
		{
			name:     "unicode",
			input:    "文件",
			expected: "%E6%96%87%E4%BB%B6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := uriEncode(tt.input)
			if result != tt.expected {
				t.Errorf("uriEncode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
