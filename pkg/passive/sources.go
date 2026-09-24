package passive

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitalyama"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/domainsproject"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hudsonrock"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/jsmon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/merklemap"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/onyphe"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/profundis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/pugrecon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconeer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rsecloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/submd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/thc"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/windvane"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var AllSources = [...]subscraping.Source{
	&alienvault.Source{},
	&anubis.Source{},
	&bevigil.Source{},
	&bufferover.Source{},
	&builtwith.Source{},
	&c99.Source{},
	&censys.Source{},
	&certspotter.Source{},
	&chaos.Source{},
	&chinaz.Source{},
	&commoncrawl.Source{},
	&crtsh.Source{},
	&digitalyama.Source{},
	&digitorus.Source{},
	&dnsdb.Source{},
	&dnsdumpster.Source{},
	&dnsrepo.Source{},
	&domainsproject.Source{},
	&driftnet.Source{},
	&fofa.Source{},
	&fullhunt.Source{},
	&github.Source{},
	&hackertarget.Source{},
	&hudsonrock.Source{},
	&intelx.Source{},
	&jsmon.Source{},
	&leakix.Source{},
	&merklemap.Source{},
	&netlas.Source{},
	&onyphe.Source{},
	&profundis.Source{},
	&pugrecon.Source{},
	&quake.Source{},
	&rapiddns.Source{},
	// &reconcloud.Source{}, // failing due to cloudflare bot protection
	&reconeer.Source{},
	&redhuntlabs.Source{},
	// &riddler.Source{}, // failing due to cloudfront protection
	&robtex.Source{},
	&rsecloud.Source{},
	&securitytrails.Source{},
	&shodan.Source{},
	&sitedossier.Source{},
	&thc.Source{},
	&threatbook.Source{},
	&threatcrowd.Source{},
	// &threatminer.Source{}, // failing  api
	&urlscan.Source{},
	&virustotal.Source{},
	&waybackarchive.Source{},
	&whoisxmlapi.Source{},
	&windvane.Source{},
	&zoomeyeapi.Source{},
	&submd.Source{},
}

var SourceFactories = map[string]func() subscraping.Source{
	"alienvault":     func() subscraping.Source { return &alienvault.Source{} },
	"anubis":         func() subscraping.Source { return &anubis.Source{} },
	"bevigil":        func() subscraping.Source { return &bevigil.Source{} },
	"bufferover":     func() subscraping.Source { return &bufferover.Source{} },
	"builtwith":      func() subscraping.Source { return &builtwith.Source{} },
	"c99":            func() subscraping.Source { return &c99.Source{} },
	"censys":         func() subscraping.Source { return &censys.Source{} },
	"certspotter":    func() subscraping.Source { return &certspotter.Source{} },
	"chaos":          func() subscraping.Source { return &chaos.Source{} },
	"chinaz":         func() subscraping.Source { return &chinaz.Source{} },
	"commoncrawl":    func() subscraping.Source { return &commoncrawl.Source{} },
	"crtsh":          func() subscraping.Source { return &crtsh.Source{} },
	"digitalyama":    func() subscraping.Source { return &digitalyama.Source{} },
	"digitorus":      func() subscraping.Source { return &digitorus.Source{} },
	"dnsdb":          func() subscraping.Source { return &dnsdb.Source{} },
	"dnsdumpster":    func() subscraping.Source { return &dnsdumpster.Source{} },
	"dnsrepo":        func() subscraping.Source { return &dnsrepo.Source{} },
	"domainsproject": func() subscraping.Source { return &domainsproject.Source{} },
	"driftnet":       func() subscraping.Source { return &driftnet.Source{} },
	"fofa":           func() subscraping.Source { return &fofa.Source{} },
	"fullhunt":       func() subscraping.Source { return &fullhunt.Source{} },
	"github":         func() subscraping.Source { return &github.Source{} },
	"hackertarget":   func() subscraping.Source { return &hackertarget.Source{} },
	"hudsonrock":     func() subscraping.Source { return &hudsonrock.Source{} },
	"intelx":         func() subscraping.Source { return &intelx.Source{} },
	"jsmon":          func() subscraping.Source { return &jsmon.Source{} },
	"leakix":         func() subscraping.Source { return &leakix.Source{} },
	"merklemap":      func() subscraping.Source { return &merklemap.Source{} },
	"netlas":         func() subscraping.Source { return &netlas.Source{} },
	"onyphe":         func() subscraping.Source { return &onyphe.Source{} },
	"profundis":      func() subscraping.Source { return &profundis.Source{} },
	"pugrecon":       func() subscraping.Source { return &pugrecon.Source{} },
	"quake":          func() subscraping.Source { return &quake.Source{} },
	"rapiddns":       func() subscraping.Source { return &rapiddns.Source{} },
	"reconeer":       func() subscraping.Source { return &reconeer.Source{} },
	"redhuntlabs":    func() subscraping.Source { return &redhuntlabs.Source{} },
	"robtex":         func() subscraping.Source { return &robtex.Source{} },
	"rsecloud":       func() subscraping.Source { return &rsecloud.Source{} },
	"securitytrails": func() subscraping.Source { return &securitytrails.Source{} },
	"shodan":         func() subscraping.Source { return &shodan.Source{} },
	"sitedossier":    func() subscraping.Source { return &sitedossier.Source{} },
	"submd":          func() subscraping.Source { return &submd.Source{} },
	"thc":            func() subscraping.Source { return &thc.Source{} },
	"threatbook":     func() subscraping.Source { return &threatbook.Source{} },
	"threatcrowd":    func() subscraping.Source { return &threatcrowd.Source{} },
	"urlscan":        func() subscraping.Source { return &urlscan.Source{} },
	"virustotal":     func() subscraping.Source { return &virustotal.Source{} },
	"waybackarchive": func() subscraping.Source { return &waybackarchive.Source{} },
	"whoisxmlapi":    func() subscraping.Source { return &whoisxmlapi.Source{} },
	"windvane":       func() subscraping.Source { return &windvane.Source{} },
	"zoomeyeapi":     func() subscraping.Source { return &zoomeyeapi.Source{} },
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{}))

var NameSourceMap = make(map[string]subscraping.Source, len(AllSources))

func init() {
	for _, currentSource := range AllSources {
		NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
	}
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []subscraping.Source
}

func NewAgent(sources []subscraping.Source) *Agent {
	return &Agent{sources: sources}
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	return NewWithProviderKeys(sourceNames, excludedSourceNames, useAllSources, useSourcesSupportingRecurse, nil)
}

// NewWithProviderKeys creates an agent with fresh source instances and applies
// provider keys to those instances instead of mutating package-level sources.
func NewWithProviderKeys(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool, providerKeys map[string][]string) *Agent {
	sources := make(map[string]subscraping.Source, len(AllSources))

	if useAllSources {
		for sourceName := range NameSourceMap {
			if source := NewSource(sourceName); source != nil {
				sources[sourceName] = source
			}
		}
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				sourceName := strings.ToLower(source)
				if NameSourceMap[sourceName] == nil {
					gologger.Warning().Msgf("There is no source with the name: %s", source)
				} else {
					sources[sourceName] = NewSource(sourceName)
				}
			}
		} else {
			for _, currentSource := range AllSources {
				if currentSource.IsDefault() {
					sourceName := strings.ToLower(currentSource.Name())
					sources[sourceName] = NewSource(sourceName)
				}
			}
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}

	if len(sources) == 0 {
		gologger.Fatal().Msg("No sources selected for this search")
	}

	gologger.Debug().Msgf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", "))

	for _, currentSource := range sources {
		if warning, ok := sourceWarnings.Get(strings.ToLower(currentSource.Name())); ok {
			gologger.Warning().Msg(warning)
		}
	}

	for _, source := range sources {
		keyReq := source.KeyRequirement()
		if keyReq == subscraping.RequiredKey || keyReq == subscraping.OptionalKey {
			sourceName := strings.ToLower(source.Name())
			if apiKeys := providerKeys[sourceName]; len(apiKeys) > 0 {
				source.AddApiKeys(apiKeys)
			} else if apiKey := os.Getenv(fmt.Sprintf("%s_API_KEY", strings.ToUpper(source.Name()))); apiKey != "" {
				source.AddApiKeys([]string{apiKey})
			}
		}
	}

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}

	return agent
}

// NewSource returns a fresh source instance for a source name.
func NewSource(sourceName string) subscraping.Source {
	factory := SourceFactories[strings.ToLower(sourceName)]
	if factory == nil {
		return nil
	}
	return factory()
}

// NewSources returns fresh instances for all known source names.
func NewSources() []subscraping.Source {
	sources := make([]subscraping.Source, 0, len(SourceFactories))
	for sourceName := range NameSourceMap {
		if source := NewSource(sourceName); source != nil {
			sources = append(sources, source)
		}
	}
	return sources
}
