package runner

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/goflags"
	"gopkg.in/yaml.v3"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	fileutil "github.com/projectdiscovery/utils/file"
)

// createProviderConfigYAML marshals the input map to the given location on the disk
func createProviderConfigYAML(configFilePath string) error {
	configFile, err := os.Create(configFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := configFile.Close(); err != nil {
			gologger.Error().Msgf("Error closing config file: %s", err)
		}
	}()

	sourcesRequiringApiKeysMap := make(map[string][]string)
	for _, source := range passive.AllSources {
		keyReq := source.KeyRequirement()
		if keyReq == subscraping.RequiredKey || keyReq == subscraping.OptionalKey {
			sourceName := strings.ToLower(source.Name())
			sourcesRequiringApiKeysMap[sourceName] = []string{}
		}
	}

	return yaml.NewEncoder(configFile).Encode(sourcesRequiringApiKeysMap)
}

// UnmarshalFrom writes the marshaled yaml config to disk
func UnmarshalFrom(file string) error {
	sourceApiKeysMap, err := LoadProviderConfig(file)
	if err != nil {
		return err
	}

	for _, source := range passive.AllSources {
		sourceName := strings.ToLower(source.Name())
		apiKeys := sourceApiKeysMap[sourceName]
		if len(apiKeys) > 0 {
			gologger.Debug().Msgf("API key(s) found for %s.", sourceName)
			source.AddApiKeys(apiKeys)
		}
	}
	return err
}

// LoadProviderConfig loads source API keys from a provider config file without
// mutating package-level source instances.
func LoadProviderConfig(file string) (map[string][]string, error) {
	reader, err := fileutil.SubstituteConfigFromEnvVars(file)
	if err != nil {
		return nil, err
	}

	sourceApiKeysMap := map[string][]string{}
	if err := yaml.NewDecoder(reader).Decode(sourceApiKeysMap); err != nil {
		return nil, err
	}

	for sourceName, apiKeys := range sourceApiKeysMap {
		normalizedSourceName := strings.ToLower(sourceName)
		delete(sourceApiKeysMap, sourceName)
		for _, apiKey := range apiKeys {
			if strings.TrimSpace(apiKey) != "" {
				sourceApiKeysMap[normalizedSourceName] = append(sourceApiKeysMap[normalizedSourceName], apiKey)
			}
		}
	}

	return sourceApiKeysMap, nil
}

// FreshSourcesFromOptions returns fresh source instances selected from runner
// options and configured with provider keys from options.ProviderConfig.
func FreshSourcesFromOptions(options Options) ([]subscraping.Source, map[string][]string, error) {
	providerKeys := map[string][]string{}
	if options.ProviderConfig != "" && fileutil.FileExists(options.ProviderConfig) {
		loaded, err := LoadProviderConfig(options.ProviderConfig)
		if err != nil {
			return nil, nil, err
		}
		providerKeys = loaded
	}

	sources, err := SelectFreshSources(options.Sources, options.ExcludeSources, options.All, options.OnlyRecursive, providerKeys)
	if err != nil {
		return nil, nil, err
	}
	return sources, providerKeys, nil
}

// SelectFreshSources returns fresh source instances for the same source flags
// used by the runner. Required-key sources are selected only when provider keys
// or a matching SOURCE_API_KEY environment variable are present.
func SelectFreshSources(sourceNames, excludedSourceNames goflags.StringSlice, useAllSources, useSourcesSupportingRecurse bool, providerKeys map[string][]string) ([]subscraping.Source, error) {
	excluded := make(map[string]struct{}, len(excludedSourceNames))
	for _, name := range excludedSourceNames {
		excluded[strings.ToLower(name)] = struct{}{}
	}

	sources := make(map[string]subscraping.Source, len(passive.AllSources))
	if useAllSources {
		for sourceName := range passive.NameSourceMap {
			if source := passive.NewSource(sourceName); source != nil {
				sources[sourceName] = source
			}
		}
	} else if len(sourceNames) > 0 {
		for _, sourceName := range sourceNames {
			sourceName := strings.ToLower(sourceName)
			source := passive.NewSource(sourceName)
			if source == nil {
				gologger.Warning().Msgf("There is no source with the name: %s", sourceName)
				continue
			}
			sources[sourceName] = source
		}
	} else {
		for _, source := range passive.NewSources() {
			if source.IsDefault() {
				sources[strings.ToLower(source.Name())] = source
			}
		}
	}

	selected := make([]subscraping.Source, 0, len(sources))
	for sourceName, source := range sources {
		if _, ok := excluded[sourceName]; ok {
			continue
		}
		if useSourcesSupportingRecurse && !source.HasRecursiveSupport() {
			continue
		}
		if !shouldSelectSource(source, providerKeys) {
			continue
		}
		if err := configureSource(source, providerKeys); err != nil {
			return nil, err
		}
		selected = append(selected, source)
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no sources selected for this search")
	}
	return selected, nil
}

func shouldSelectSource(source subscraping.Source, providerKeys map[string][]string) bool {
	if source.KeyRequirement() != subscraping.RequiredKey {
		return true
	}
	sourceName := strings.ToLower(source.Name())
	if len(providerKeys[sourceName]) > 0 {
		return true
	}
	return os.Getenv(fmt.Sprintf("%s_API_KEY", strings.ToUpper(sourceName))) != ""
}

func configureSource(source subscraping.Source, providerKeys map[string][]string) error {
	keyReq := source.KeyRequirement()
	if keyReq != subscraping.RequiredKey && keyReq != subscraping.OptionalKey {
		return nil
	}

	sourceName := strings.ToLower(source.Name())
	if apiKeys := providerKeys[sourceName]; len(apiKeys) > 0 {
		source.AddApiKeys(apiKeys)
		return nil
	}
	if apiKey := os.Getenv(fmt.Sprintf("%s_API_KEY", strings.ToUpper(sourceName))); apiKey != "" {
		source.AddApiKeys([]string{apiKey})
	}
	return nil
}
