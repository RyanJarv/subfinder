package jsmon

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func testSession(t *testing.T) (context.Context, *subscraping.Session) {
	t.Helper()
	ctx := context.WithValue(context.Background(), subscraping.CtxSourceArg, "jsmon")
	limiter, err := ratelimit.NewMultiLimiter(ctx, &ratelimit.Options{Key: "jsmon", MaxCount: math.MaxInt32, Duration: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Stop() })
	return ctx, &subscraping.Session{Client: &http.Client{}, MultiRateLimiter: limiter}
}

func TestPaginatedResultsAndScopedHosts(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Key") != "test-key" {
			t.Errorf("API key header missing")
		}
		pages = append(pages, r.URL.Query().Get("page"))
		if r.URL.Path != "/api/domain/example.com" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if len(pages) == 1 {
			fmt.Fprint(w, `{"page":1,"total_pages":2,"subdomains":["API.Example.COM.","outside.test"]}`)
		} else {
			fmt.Fprint(w, `{"page":2,"total_pages":2,"subdomains":["www.example.com"]}`)
		}
	}))
	defer server.Close()
	ctx, session := testSession(t)
	source := &Source{baseURL: server.URL + "/api/domain/"}
	source.AddApiKeys([]string{"test-key"})
	var got []string
	for result := range source.Run(ctx, "example.com", session) {
		if result.Type != subscraping.Subdomain {
			t.Fatalf("unexpected error: %v", result.Error)
		}
		got = append(got, result.Value)
	}
	if !reflect.DeepEqual(got, []string{"api.example.com", "www.example.com"}) || !reflect.DeepEqual(pages, []string{"1", "2"}) {
		t.Fatalf("results = %v, pages = %v", got, pages)
	}
}

func TestLaterProviderErrorPreservesEarlierResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			fmt.Fprint(w, `{"page":1,"total_pages":2,"subdomains":["one.example.com"]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	ctx, session := testSession(t)
	source := &Source{baseURL: server.URL + "/api/domain/"}
	source.AddApiKeys([]string{"test-key"})
	var got []subscraping.Result
	for result := range source.Run(ctx, "example.com", session) {
		got = append(got, result)
	}
	if len(got) != 2 || got[0].Value != "one.example.com" || got[1].Type != subscraping.Error || source.Statistics().Results != 1 || source.Statistics().Errors != 1 {
		t.Fatalf("results = %+v, stats = %+v", got, source.Statistics())
	}
}

func TestRedirectDoesNotForwardKey(t *testing.T) {
	forwarded := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Api-Key") != ""
	}))
	defer destination.Close()
	server := httptest.NewServer(http.RedirectHandler(destination.URL, http.StatusFound))
	defer server.Close()
	ctx, session := testSession(t)
	source := &Source{baseURL: server.URL + "/api/domain/"}
	source.AddApiKeys([]string{"test-key"})
	for range source.Run(ctx, "example.com", session) {
	}
	if forwarded || source.Statistics().Errors != 1 {
		t.Fatalf("redirect forwarded key = %t, stats = %+v", forwarded, source.Statistics())
	}
}

func TestMissingKeySkipsWithoutRequest(t *testing.T) {
	ctx, session := testSession(t)
	source := &Source{}
	for result := range source.Run(ctx, "example.com", session) {
		t.Fatalf("unexpected result without key: %+v", result)
	}
	if stats := source.Statistics(); !stats.Skipped || stats.Requests != 0 {
		t.Fatalf("stats = %+v, want skipped without requests", stats)
	}
}

func TestMalformedPageReportsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"page":2,"total_pages":2,"subdomains":["one.example.com"]}`)
	}))
	defer server.Close()
	ctx, session := testSession(t)
	source := &Source{baseURL: server.URL + "/api/domain/"}
	source.AddApiKeys([]string{"test-key"})
	var got []subscraping.Result
	for result := range source.Run(ctx, "example.com", session) {
		got = append(got, result)
	}
	if len(got) != 1 || got[0].Type != subscraping.Error {
		t.Fatalf("results = %+v, want invalid-page error", got)
	}
}

type trackingBody struct {
	reader io.Reader
	read   int
	closed bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOversizedPageDoesNotDrainResponse(t *testing.T) {
	ctx, session := testSession(t)
	body := &trackingBody{reader: strings.NewReader(strings.Repeat("x", maxPageBytes*2))}
	session.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})
	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	var got []subscraping.Result
	for result := range source.Run(ctx, "example.com", session) {
		got = append(got, result)
	}
	if len(got) != 1 || got[0].Type != subscraping.Error || body.read > maxPageBytes+1 || !body.closed {
		t.Fatalf("results = %+v, read = %d, closed = %t", got, body.read, body.closed)
	}
}
