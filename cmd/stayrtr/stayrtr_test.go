package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"github.com/bgp/stayrtr/prefixfile"
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
