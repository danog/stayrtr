package utils

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		{name: "bogus huge hint", input: "abcdef", sizeHint: 1 << 50},
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

func TestFetchFileStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never honors conditional requests: the IdenticalEtag short-circuit
		// triggers on a 200 response whose etag matches the stored one.
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "12")
		io.WriteString(w, "hello stream")
	}))
	defer srv.Close()

	c := NewFetchConfig()
	c.EnableEtags = true

	stream, code, lastrefresh, err := c.FetchFileStream(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if code != -1 || lastrefresh {
		t.Fatalf("got code=%d lastrefresh=%v, want code=-1 lastrefresh=false", code, lastrefresh)
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello stream" {
		t.Fatalf("got %q, want %q", data, "hello stream")
	}

	// The stored etag must short-circuit the next fetch.
	_, code, lastrefresh, err = c.FetchFileStream(srv.URL)
	if _, ok := err.(IdenticalEtag); !ok {
		t.Fatalf("got err=%v (%T), want IdenticalEtag", err, err)
	}
	if code != 200 || !lastrefresh {
		t.Fatalf("got code=%d lastrefresh=%v, want code=200 lastrefresh=true", code, lastrefresh)
	}
}

func TestFetchFileStreamNotModified(t *testing.T) {
	etagSeen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			etagSeen = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, "hello stream")
	}))
	defer srv.Close()

	c := NewFetchConfig()
	c.EnableEtags = true

	stream, _, _, err := c.FetchFileStream(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	_, code, lastrefresh, err := c.FetchFileStream(srv.URL)
	if _, ok := err.(HttpNotModified); !ok {
		t.Fatalf("got err=%v (%T), want HttpNotModified", err, err)
	}
	if code != 304 || !lastrefresh {
		t.Fatalf("got code=%d lastrefresh=%v, want code=304 lastrefresh=true", code, lastrefresh)
	}
	if !etagSeen {
		t.Fatal("conditional request did not reach the server")
	}
}

func TestFetchFileStreamHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewFetchConfig()
	_, code, lastrefresh, err := c.FetchFileStream(srv.URL)
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
	if code != 404 || !lastrefresh {
		t.Fatalf("got code=%d lastrefresh=%v, want code=404 lastrefresh=true", code, lastrefresh)
	}
}

func TestFetchFileMatchesStream(t *testing.T) {
	body := "the whole document"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer srv.Close()

	c := NewFetchConfig()
	data, code, lastrefresh, err := c.FetchFile(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if code != -1 || lastrefresh {
		t.Fatalf("got code=%d lastrefresh=%v, want code=-1 lastrefresh=false", code, lastrefresh)
	}
	if string(data) != body {
		t.Fatalf("got %q, want %q", data, body)
	}

	local := filepath.Join(t.TempDir(), "doc.txt")
	if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _, _, err = c.FetchFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != body {
		t.Fatalf("got %q, want %q", data, body)
	}
}
