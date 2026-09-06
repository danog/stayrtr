package utils

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type FetchConfig struct {
	UserAgent string
	Mime      string

	etags                  map[string]string
	lastModified           map[string]time.Time
	conditionalRequestLock *sync.RWMutex
	EnableEtags            bool
	EnableLastModified     bool
}

func NewFetchConfig() *FetchConfig {
	return &FetchConfig{
		etags:                  make(map[string]string),
		lastModified:           make(map[string]time.Time),
		conditionalRequestLock: &sync.RWMutex{},
		Mime:                   "application/json",
	}
}

type HttpNotModified struct {
	File string
}

func (e HttpNotModified) Error() string {
	return fmt.Sprintf("HTTP 304 Not modified for %s", e.File)
}

type IdenticalEtag struct {
	File string
	Etag string
}

func (e IdenticalEtag) Error() string {
	return fmt.Sprintf("File %s is identical according to Etag: %s", e.File, e.Etag)
}

// FetchStream is an opened fetch of a remote or local file. The embedded
// reader must be consumed and then closed by the caller; Close also releases
// the underlying HTTP connection resources.
type FetchStream struct {
	io.ReadCloser

	// SizeHint is a best-effort expected size of the stream in bytes, or -1
	// when unknown (e.g. transparently decompressed HTTP responses carry no
	// usable Content-Length).
	SizeHint int64

	closeOnce sync.Once
	closeFn   func()
}

func (s *FetchStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.closeFn != nil {
			s.closeFn()
		}
		if s.ReadCloser != nil {
			err = s.ReadCloser.Close()
		}
	})
	return err
}

// FetchFileStream opens file for streaming without buffering the whole body in
// memory. Callers that want the complete body in one slice can use FetchFile.
// The returned status code and lastrefresh flag mirror FetchFile: code is -1
// for local files and successful responses carry -1 as well, while
// conditional-request hits and HTTP errors are reported through the error
// return together with the HTTP status code.
func (c *FetchConfig) FetchFileStream(file string) (*FetchStream, int, bool, error) {
	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {

		// Copying base of DefaultTransport from https://golang.org/src/net/http/transport.go
		// There is a proposal for a Clone of
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ProxyConnectHeader:    map[string][]string{},
		}
		// Keep User-Agent in proxy request
		tr.ProxyConnectHeader.Set("User-Agent", c.UserAgent)

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", file, nil)
		if err != nil {
			return nil, -1, false, err
		}

		req.Header.Set("User-Agent", c.UserAgent)
		if c.Mime != "" {
			req.Header.Set("Accept", c.Mime)
		}

		c.conditionalRequestLock.RLock()
		if c.EnableEtags {
			etag, ok := c.etags[file]
			if ok {
				req.Header.Set("If-None-Match", etag)
			}
		}
		if c.EnableLastModified {
			lastModified, ok := c.lastModified[file]
			if ok {
				req.Header.Set("If-Modified-Since", lastModified.UTC().Format(http.TimeFormat))
			}
		}
		c.conditionalRequestLock.RUnlock()

		proxyurl, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, -1, false, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		if err != nil {
			return nil, -1, false, err
		}

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, -1, false, err
		}
		closeAll := func() {
			if fhttp.Body != nil {
				fhttp.Body.Close()
			}
			client.CloseIdleConnections()
		}
		//RefreshStatusCode.WithLabelValues(file, fmt.Sprintf("%d", fhttp.StatusCode)).Inc()

		if fhttp.StatusCode == 304 {
			//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))
			closeAll()
			return nil, fhttp.StatusCode, true, HttpNotModified{
				File: file,
			}
		} else if fhttp.StatusCode != 200 {
			c.conditionalRequestLock.Lock()
			delete(c.etags, file)
			delete(c.lastModified, file)
			c.conditionalRequestLock.Unlock()
			closeAll()
			return nil, fhttp.StatusCode, true, fmt.Errorf("HTTP %s", fhttp.Status)
		}
		//LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))

		newEtag := fhttp.Header.Get("ETag")

		if !c.EnableEtags || newEtag == "" || newEtag != c.etags[file] { // check lock here
			c.conditionalRequestLock.Lock()
			c.etags[file] = newEtag
			c.conditionalRequestLock.Unlock()
		} else {
			closeAll()
			return nil, fhttp.StatusCode, true, IdenticalEtag{
				File: file,
				Etag: newEtag,
			}
		}

		if c.EnableLastModified {
			// Accept any valid Last-Modified values. Because of the 1s resolution,
			// getting the same value is not an error (c.f. the IdenticalEtag error).
			ifModifiedSince, err := http.ParseTime(fhttp.Header.Get("Last-Modified"))
			c.conditionalRequestLock.Lock()
			if err == nil {
				c.lastModified[file] = ifModifiedSince
			} else {
				delete(c.lastModified, file)
			}
			c.conditionalRequestLock.Unlock()
		}

		return &FetchStream{
			ReadCloser: fhttp.Body,
			SizeHint:   fhttp.ContentLength,
			closeFn:    client.CloseIdleConnections,
		}, -1, false, nil
	}

	localFile, err := os.Open(file)
	if err != nil {
		return nil, -1, false, err
	}
	stream := &FetchStream{ReadCloser: localFile, SizeHint: -1}
	if stat, statErr := localFile.Stat(); statErr == nil {
		stream.SizeHint = stat.Size()
	}
	return stream, -1, false, nil
}

// FetchFile fetches file and returns the complete body in memory. It is a
// wrapper around FetchFileStream for callers that do not benefit from
// streaming.
func (c *FetchConfig) FetchFile(file string) ([]byte, int, bool, error) {
	stream, code, lastrefresh, err := c.FetchFileStream(file)
	if err != nil {
		return nil, code, lastrefresh, err
	}
	defer stream.Close()
	data, err := readAllWithSizeHint(stream, stream.SizeHint)
	if err != nil {
		return nil, -1, false, err
	}
	return data, code, lastrefresh, nil
}

func readAllWithSizeHint(r io.Reader, sizeHint int64) ([]byte, error) {
	maxInt := uint64(^uint(0) >> 1)
	if sizeHint <= 0 || uint64(sizeHint) > maxInt {
		return io.ReadAll(r)
	}

	data := make([]byte, int(sizeHint))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	// Content-Length and regular-file sizes should be exact. Preserve correct
	// behavior if a reader grows after the size was observed.
	var extra [1]byte
	n, err := r.Read(extra[:])
	if err == io.EOF {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	tail, err := io.ReadAll(r)
	data = append(data, extra[:n]...)
	data = append(data, tail...)
	return data, err
}
