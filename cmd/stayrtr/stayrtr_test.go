package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/prefixfile"
	"github.com/bgp/stayrtr/utils"
	"github.com/google/go-cmp/cmp"
)

func TestProcessData(t *testing.T) {
	var stuff []prefixfile.VRPJson
	NowUnix := time.Now().Unix()
	ExpiredTime := int64(1337)

	stuff = append(stuff,
		prefixfile.VRPJson{
			Prefix:  "192.168.0.0/24",
			Length:  24,
			ASN:     123,
			TA:      "testrir",
			Expires: &NowUnix,
		},
		prefixfile.VRPJson{
			Prefix: "192.168.0.0/24",
			Length: 24,
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "2001:db8::/32",
			Length: 33,
			ASN:    "AS123",
			TA:     "testrir",
		},
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 25,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Length is 0
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 0,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Length less than prefix length
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 16,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. 129 is invalid for IPv6
		prefixfile.VRPJson{
			Prefix: "2001:db8::/32",
			Length: 129,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. 33 is invalid for IPv4
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/24",
			Length: 33,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Not a prefix
		prefixfile.VRPJson{
			Prefix: "192.168.1.0",
			Length: 24,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Not a prefix
		prefixfile.VRPJson{
			Prefix: "👻",
			Length: 24,
			ASN:    123,
			TA:     "testrir",
		},
		// Invalid. Invalid ASN string
		prefixfile.VRPJson{
			Prefix: "192.168.1.0/22",
			Length: 22,
			ASN:    "ASN123",
			TA:     "testrir",
		},
		// Invalid. Has expired
		prefixfile.VRPJson{
			Prefix:  "192.168.2.0/24",
			Length:  24,
			ASN:     124,
			TA:      "testrir",
			Expires: &ExpiredTime,
		},
	)
	got, _, v4count, v6count := processData(stuff, nil)
	want := []rtr.VRP{
		{
			Prefix: netip.MustParsePrefix("2001:db8::/32"),
			MaxLen: 33,
			ASN:    123,
		},
		{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			MaxLen: 25,
			ASN:    123,
		},
		{
			Prefix: netip.MustParsePrefix("192.168.0.0/24"),
			MaxLen: 24,
			ASN:    123,
		},
	}
	if v4count != 2 || v6count != 1 {
		t.Errorf("Wanted v4count = 2, v6count = 1, but got %d, %d", v4count, v6count)
	}

	opts := []cmp.Option{
		cmp.Comparer(func(x, y netip.Prefix) bool {
			return x == y
		}),
	}

	if !cmp.Equal(got, want, opts...) {
		t.Errorf("Want (%+v), Got (%+v)", want, got)
	}
}

func TestProcessDataDeduplicatesWithoutDroppingOtherASNs(t *testing.T) {
	input := []prefixfile.VRPJson{
		{Prefix: "192.0.2.0/24", Length: 24, ASN: 64497},
		{Prefix: "192.0.2.0/24", Length: 24, ASN: 64496},
		{Prefix: "192.0.2.0/24", Length: 24, ASN: 64497},
	}

	got, _, v4count, v6count := processData(input, nil)
	want := []rtr.VRP{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLen: 24, ASN: 64496},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLen: 24, ASN: 64497},
	}

	if diff := cmp.Diff(want, got, cmp.Comparer(func(x, y netip.Prefix) bool { return x == y })); diff != "" {
		t.Fatalf("unexpected VRPs (-want +got):\n%s", diff)
	}
	if v4count != 3 || v6count != 0 {
		t.Fatalf("got input counts v4=%d v6=%d, want v4=3 v6=0", v4count, v6count)
	}
}

func BenchmarkDecodeJSON(b *testing.B) {
	json, err := os.ReadFile("test.rpki.json")
	if err != nil {
		panic(err)
	}
	for n := 0; n < b.N; n++ {
		decodeJSON(json)
	}
}

func TestJson(t *testing.T) {
	json, err := os.ReadFile("smalltest.rpki.json")
	if err != nil {
		panic(err)
	}
	got, err := decodeJSON(json)
	if err != nil {
		t.Errorf("Unable to decode json: %v", err)
	}

	Ex1 := int64(1627568318)
	Ex2 := int64(1627575699)

	want := (&prefixfile.RPKIList{
		Metadata: prefixfile.MetaData{
			Counts:    2,
			Buildtime: "2021-07-27T18:56:02Z",
		},
		ROA: []prefixfile.VRPJson{
			{Prefix: "1.0.0.0/24",
				Length:  24,
				ASN:     float64(13335),
				TA:      "apnic",
				Expires: &Ex1,
			},
			{
				Prefix:  "2001:200:136::/48",
				Length:  48,
				ASN:     "AS9367",
				TA:      "apnic",
				Expires: &Ex2,
			},
		},
	})

	if !cmp.Equal(got, want) {
		t.Errorf("Got (%v), Wanted (%v)", got, want)
	}

}

func TestNewSHA256(t *testing.T) {
	want := "8eddd6897b244bb4d045ff811128b50b53ed85d19a9d1b756a0a400e82b23c2f"
	got := fmt.Sprintf("%x", newSHA256([]byte("☘️")))
	if got != want {
		t.Errorf("Got (%s), Wanted (%s)", got, want)
	}
}

func TestRegisterPprofHandlers(t *testing.T) {
	mux := http.NewServeMux()
	registerPprofHandlers(mux)

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Errorf("GET %s: got status %d, want %d", path, res.Code, http.StatusOK)
		}
	}
}

func TestExporter(t *testing.T) {
	want := prefixfile.RPKIList{
		Metadata: prefixfile.MetaData{Counts: 2, Serial: 42},
		ROA: []prefixfile.VRPJson{
			{Prefix: "192.0.2.0/24", Length: 24, ASN: float64(64496), TA: "test"},
			{Prefix: "2001:db8::/32", Length: 48, ASN: "AS64497", TA: "test"},
		},
		BgpSecKeys: []prefixfile.BgpSecKeyJson{
			{Asn: 64496, Pubkey: []byte("key"), Ski: "abcd"},
		},
	}
	s := state{exported: want, lockJson: &sync.RWMutex{}}
	res := httptest.NewRecorder()
	s.exporter(res, httptest.NewRequest(http.MethodGet, "/rpki.json", nil))

	if got := res.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("got Content-Type %q, want application/json", got)
	}
	var got prefixfile.RPKIList
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatalf("exported invalid JSON: %v", err)
	}
	if !cmp.Equal(got, want) {
		t.Fatalf("unexpected export (-want +got):\n%s", cmp.Diff(want, got))
	}
}

func TestUnchangedUpdateRefreshesExport(t *testing.T) {
	server := rtr.NewServer(rtr.ServerConfiguration{KeepDifference: 3}, nil, nil)
	s := state{
		server:           server,
		lastdata:         &prefixfile.RPKIList{Metadata: prefixfile.MetaData{Buildtime: "first"}},
		lockJson:         &sync.RWMutex{},
		exportEnabled:    true,
		retainSourceData: true,
	}
	vrps := []rtr.VRP{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLen: 24, ASN: 64496}}
	first := []prefixfile.VRPJson{{Prefix: "192.0.2.0/24", Length: 24, ASN: 64496, TA: "first"}}
	if err := s.applyUpdateFromNewState(vrps, nil, first, nil, 1, 0); err != nil {
		t.Fatal(err)
	}

	s.lastdata = &prefixfile.RPKIList{Metadata: prefixfile.MetaData{Buildtime: "second"}}
	second := []prefixfile.VRPJson{{Prefix: "192.0.2.0/24", Length: 24, ASN: 64496, TA: "second"}}
	if err := s.applyUpdateFromNewState(vrps, nil, second, nil, 1, 0); err != nil {
		t.Fatal(err)
	}

	if s.exported.Metadata.Buildtime != "second" || s.exported.ROA[0].TA != "second" {
		t.Fatalf("unchanged RTR update left stale export: %+v", s.exported)
	}
}

func TestUpdateReleasesSourceDataWhenUnused(t *testing.T) {
	server := rtr.NewServer(rtr.ServerConfiguration{KeepDifference: 3}, nil, nil)
	s := state{
		server:   server,
		lastdata: &prefixfile.RPKIList{ROA: []prefixfile.VRPJson{{Prefix: "192.0.2.0/24", Length: 24, ASN: 64496}}},
		lockJson: &sync.RWMutex{},
	}

	if err := s.updateFromNewState(); err != nil {
		t.Fatal(err)
	}
	if s.lastdata.ROA != nil || s.lastdata.BgpSecKeys != nil {
		t.Fatal("decoded source data was retained with export and SLURM disabled")
	}
	if got := server.CountSDs(); got != 1 {
		t.Fatalf("RTR state contains %d objects, want 1", got)
	}
}

func TestDecodeJSONStreamMatchesUnmarshal(t *testing.T) {
	data, err := os.ReadFile("test.rpki.json")
	if err != nil {
		t.Fatal(err)
	}
	prefixComparer := cmp.Comparer(func(x, y netip.Prefix) bool { return x == y })

	wantList, err := decodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	wantVrps, wantBrks, wantV4, wantV6 := processData(wantList.ROA, wantList.BgpSecKeys)

	got, err := decodeJSONStream(bytes.NewReader(data), int64(len(data)), true)
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(wantList.Metadata, got.metadata) {
		t.Fatalf("metadata mismatch (-want +got):\n%s", cmp.Diff(wantList.Metadata, got.metadata))
	}
	if !cmp.Equal(wantList.ROA, got.vrpsjson) {
		t.Fatalf("retained ROAs mismatch (-want +got):\n%s", cmp.Diff(wantList.ROA, got.vrpsjson))
	}
	if !cmp.Equal(wantList.BgpSecKeys, got.brksjson) {
		t.Fatalf("retained BGPsec keys mismatch (-want +got):\n%s", cmp.Diff(wantList.BgpSecKeys, got.brksjson))
	}
	if !cmp.Equal(wantVrps, sortAndDedupVRPs(got.vrps), prefixComparer) {
		t.Fatalf("VRPs mismatch (-want +got):\n%s", cmp.Diff(wantVrps, got.vrps, prefixComparer))
	}
	if !cmp.Equal(wantBrks, got.brks) {
		t.Fatalf("BGPsec keys mismatch (-want +got):\n%s", cmp.Diff(wantBrks, got.brks))
	}
	if got.countv4 != wantV4 || got.countv6 != wantV6 {
		t.Fatalf("got counts v4=%d v6=%d, want v4=%d v6=%d", got.countv4, got.countv6, wantV4, wantV6)
	}
}

func TestDecodeJSONStreamWithoutRetention(t *testing.T) {
	data, err := os.ReadFile("test.rpki.json")
	if err != nil {
		t.Fatal(err)
	}
	prefixComparer := cmp.Comparer(func(x, y netip.Prefix) bool { return x == y })

	retained, err := decodeJSONStream(bytes.NewReader(data), int64(len(data)), true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJSONStream(bytes.NewReader(data), int64(len(data)), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.vrpsjson != nil || got.brksjson != nil {
		t.Fatal("non-retaining decode kept raw JSON structures")
	}
	if !cmp.Equal(retained.vrps, got.vrps, prefixComparer) {
		t.Fatal("non-retaining decode produced different VRPs")
	}
	if !cmp.Equal(retained.brks, got.brks) {
		t.Fatal("non-retaining decode produced different BGPsec keys")
	}
}

func TestUpdateFileEmptyObjectIsNoop(t *testing.T) {
	dir := t.TempDir()
	doc := `{"metadata":{"vrps":2},"roas":[
		{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64496"},
		{"prefix":"2001:db8::/32","maxLength":48,"asn":"AS64497"}]}`
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(cache, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	server := rtr.NewServer(rtr.ServerConfiguration{KeepDifference: 3}, nil, nil)
	s := state{
		server:      server,
		lastdata:    &prefixfile.RPKIList{},
		lockJson:    &sync.RWMutex{},
		fetchConfig: utils.NewFetchConfig(),
	}

	if updated, err := s.updateFile(cache); err != nil || !updated {
		t.Fatalf("updateFile: updated=%v err=%v", updated, err)
	}
	if err := s.updateFromNewState(); err != nil {
		t.Fatal(err)
	}
	if got := server.CountSDs(); got != 2 {
		t.Fatalf("RTR state contains %d objects, want 2", got)
	}

	// An empty object carries no roas key and must leave the current state alone.
	if updated, err := s.updateFile(empty); err != nil || !updated {
		t.Fatalf("updateFile empty: updated=%v err=%v", updated, err)
	}
	if s.pending != nil {
		t.Fatal("empty object produced a pending update")
	}
	if err := s.updateFromNewState(); err != nil {
		t.Fatal(err)
	}
	if got := server.CountSDs(); got != 2 {
		t.Fatalf("empty object wiped the state: %d objects remain", got)
	}
}

func TestUpdateFileRetainsJSONForExport(t *testing.T) {
	dir := t.TempDir()
	doc := `{"metadata":{"vrps":1},"roas":[{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64496"}]}`
	cache := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(cache, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	server := rtr.NewServer(rtr.ServerConfiguration{KeepDifference: 3}, nil, nil)
	s := state{
		server:           server,
		lastdata:         &prefixfile.RPKIList{},
		lockJson:         &sync.RWMutex{},
		exportEnabled:    true,
		retainSourceData: true,
		fetchConfig:      utils.NewFetchConfig(),
	}

	if updated, err := s.updateFile(cache); err != nil || !updated {
		t.Fatalf("updateFile: updated=%v err=%v", updated, err)
	}
	if s.pending != nil {
		t.Fatal("retain mode produced a pending update")
	}
	if len(s.lastdata.ROA) != 1 {
		t.Fatalf("export mode retained %d raw ROAs, want 1", len(s.lastdata.ROA))
	}
	if err := s.updateFromNewState(); err != nil {
		t.Fatal(err)
	}
	if got := server.CountSDs(); got != 1 {
		t.Fatalf("RTR state contains %d objects, want 1", got)
	}
}
