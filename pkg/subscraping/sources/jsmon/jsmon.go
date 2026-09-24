// Package jsmon queries the standalone JSMon passive subdomain index.
package jsmon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	endpoint     = "https://subdomains.jsmon.sh/api/domain/"
	maxPages     = 1000
	maxPageBytes = 8 << 20
)

type pageResponse struct {
	Subdomains []string `json:"subdomains"`
	Page       int      `json:"page"`
	TotalPages int      `json:"total_pages"`
}

// Source is the JSMon passive subdomain source.
type Source struct {
	apiKeys   []string
	baseURL   string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors, s.results, s.requests = 0, 0, 0
	s.skipped = false
	go func() {
		started := time.Now()
		defer func() {
			s.timeTaken = time.Since(started)
			close(results)
		}()

		key := strings.TrimSpace(subscraping.PickRandom(s.apiKeys, s.Name()))
		if key == "" {
			s.skipped = true
			return
		}
		baseURL := s.baseURL
		if baseURL == "" {
			baseURL = endpoint
		}
		// Api-Key is a credential; a provider redirect must not forward it.
		client := *session.Client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		sourceSession := *session
		sourceSession.Client = &client

		var totalPages int
		for page := 1; page <= maxPages; page++ {
			requestURL := baseURL + url.PathEscape(domain) + "?page=" + fmt.Sprint(page)
			s.requests++
			resp, err := sourceSession.Get(ctx, requestURL, "", map[string]string{"Api-Key": key})
			if err != nil {
				s.reportError(ctx, results, fmt.Errorf("JSMon request: %w", err))
				sourceSession.DiscardHTTPResponse(resp)
				return
			}
			if resp.StatusCode == http.StatusNotFound && page == 1 {
				sourceSession.DiscardHTTPResponse(resp)
				return
			}
			if resp.StatusCode != http.StatusOK {
				s.reportError(ctx, results, fmt.Errorf("JSMon returned HTTP %d on page %d", resp.StatusCode, page))
				sourceSession.DiscardHTTPResponse(resp)
				return
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
			sourceSession.DiscardHTTPResponse(resp)
			if err != nil || len(data) > maxPageBytes {
				s.reportError(ctx, results, fmt.Errorf("JSMon page %d exceeds response limit or could not be read", page))
				return
			}
			var body pageResponse
			if err := json.Unmarshal(data, &body); err != nil || body.Subdomains == nil || body.Page != page || body.TotalPages < page && !(page == 1 && body.TotalPages == 0 && len(body.Subdomains) == 0) || totalPages != 0 && totalPages != body.TotalPages || page < body.TotalPages && len(body.Subdomains) == 0 {
				s.reportError(ctx, results, fmt.Errorf("JSMon returned invalid page %d", page))
				return
			}
			totalPages = body.TotalPages
			for _, host := range body.Subdomains {
				host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
				if !strings.HasSuffix(host, "."+strings.ToLower(domain)) {
					continue
				}
				select {
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: host}:
					s.results++
				case <-ctx.Done():
					return
				}
			}
			if page >= totalPages {
				return
			}
		}
		s.reportError(ctx, results, fmt.Errorf("JSMon exceeded %d pages", maxPages))
	}()
	return results
}

func (s *Source) reportError(ctx context.Context, results chan<- subscraping.Result, err error) {
	s.errors++
	select {
	case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
	case <-ctx.Done():
	}
}

func (s *Source) Name() string              { return "jsmon" }
func (s *Source) IsDefault() bool           { return false }
func (s *Source) HasRecursiveSupport() bool { return false }
func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}
func (s *Source) NeedsKey() bool           { return true }
func (s *Source) AddApiKeys(keys []string) { s.apiKeys = keys }
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{Errors: s.errors, Results: s.results, Requests: s.requests, TimeTaken: s.timeTaken, Skipped: s.skipped}
}
