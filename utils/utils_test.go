package utils

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadAllWithSizeHint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sizeHint int64
		wantErr  error
	}{
		{name: "exact", input: "abcdef", sizeHint: 6},
		{name: "grows", input: "abcdef", sizeHint: 3},
		{name: "unknown", input: "abcdef", sizeHint: -1},
		{name: "empty", input: "", sizeHint: 0},
		{name: "short", input: "abc", sizeHint: 6, wantErr: io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readAllWithSizeHint(strings.NewReader(tt.input), tt.sizeHint)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && string(got) != tt.input {
				t.Fatalf("got %q, want %q", got, tt.input)
			}
		})
	}
}
