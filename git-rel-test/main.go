package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// GhUpMetaAsset represents a release asset from the GitHub API relevant for UpMeta.
type GhUpMetaAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// GhUpMetaRelease represents a GitHub release with fields relevant for UpMeta processing.
type GhUpMetaRelease struct {
	TagName  string          `json:"tag_name"`
	Body     string          `json:"body"`
	Assets   []GhUpMetaAsset `json:"assets"`
	Released string          `json:"published_at"`
}

// UpMeta represents the __upmeta__ YAML structure found in release bodies.
type UpMeta struct {
	UpMetaVer string `yaml:"__upmeta__" json:"__upmeta__"`
	Format    int    `yaml:"format" json:"format"`
	Uind      int    `yaml:"uind" json:"uind"`
	Semver    string `yaml:"semver" json:"semver"`
	Channel   string `yaml:"channel" json:"channel"`

	Sources map[string]struct {
		URL            string  `yaml:"url,omitempty" json:"url"`
		Checksum       string  `yaml:"checksum" json:"checksum"`
		Signature      string  `yaml:"signature" `
		IsPatch        bool    `yaml:"is_patch" json:"is_patch"`
		PatchFor       *int    `yaml:"patch_for" json:"patch_for"`
		PatchChecksum  *string `yaml:"patch_checksum" json:"patch_checksum"`
		PatchSignature *string `yaml:"patch_signature" json:"patch_signature"`
		PatchURL       *string `yaml:"patch_url,omitempty" json:"patch_url"`
		Filename       string  `yaml:"filename,omitempty" json:"filename"`
		PatchAsset     *string `yaml:"patch_asset,omitempty" json:"patch_asset"`
	} `yaml:"sources" json:"sources"`
}

// GhUpMetaFetcher encapsulates the logic for fetching and processing
// GitHub releases to extract update metadata (`UpMeta`).
type GhUpMetaFetcher struct {
	Owner string
	Repo  string
}

// NewGhUpMetaFetcher creates a new instance of GhUpMetaFetcher.
func NewGhUpMetaFetcher(owner, repo string) *GhUpMetaFetcher {
	return &GhUpMetaFetcher{
		Owner: owner,
		Repo:  repo,
	}
}

// FetchUpMetaReleases fetches releases from GitHub, parses their bodies
// for UpMeta, and attaches asset URLs, returning processed release data.
func (gumf *GhUpMetaFetcher) FetchUpMetaReleases() ([]map[string]interface{}, error) {
	releases, err := gumf.fetchReleases()
	if err != nil {
		return nil, fmt.Errorf("error fetching releases: %w", err)
	}

	var results []map[string]interface{}

	for _, rel := range releases {
		notes, upmeta, err := gumf.parseReleaseBody(rel.Body)
		if err != nil {
			fmt.Printf("ERROR parsing release body for tag %s: %v\n", rel.TagName, err)
			continue
		}

		obj := map[string]interface{}{
			"tag":      rel.TagName,
			"notes":    notes,
			"released": rel.Released,
		}

		if upmeta != nil {
			// Attach URLs from GitHub assets
			for key, source := range upmeta.Sources {
				if url := gumf.findAssetURL(rel.Assets, source.Filename); url != nil {
					source.URL = *url
				}

				if source.PatchAsset != nil {
					if patchURL := gumf.findAssetURL(rel.Assets, *source.PatchAsset); patchURL != nil {
						source.PatchURL = patchURL
					}
				} else {
					source.PatchURL = nil
				}

				upmeta.Sources[key] = source
			}

			obj["upmeta"] = upmeta
		}

		results = append(results, obj)
	}
	return results, nil
}

// fetchReleases fetches raw GhUpMetaRelease data from the GitHub API for the
// configured owner and repository.
func (gumf *GhUpMetaFetcher) fetchReleases() ([]GhUpMetaRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", gumf.Owner, gumf.Repo)
	fmt.Println("Fetching releases from:", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	var releases []GhUpMetaRelease
	err = json.Unmarshal(bodyBytes, &releases)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	return releases, nil
}

// parseReleaseBody extracts release notes and an optional UpMeta struct
// from a GitHub release body string.
func (gumf *GhUpMetaFetcher) parseReleaseBody(body string) (string, *UpMeta, error) {
	// Extract the notes: everything before the first <details> tag
	notes := strings.TrimSpace(strings.SplitN(body, "<details>", 2)[0])

	// Match all ```yaml ... blocks
	codeBlockRe := regexp.MustCompile("(?s)```yaml\\s*\n(.*)")
	matches := codeBlockRe.FindAllStringSubmatch(body, -1)

	if matches == nil || len(matches) == 0 {
		return notes, nil, nil
	}

	for _, match := range matches {
		yamlContent := strings.TrimSpace(match[1])

		if strings.Contains(yamlContent, "__upmeta__") {
			var upmeta UpMeta
			err := yaml.Unmarshal([]byte(yamlContent), &upmeta)
			if err != nil {
				return notes, nil, fmt.Errorf("failed to parse UpMeta YAML: %w", err)
			}
			return notes, &upmeta, nil
		}
	}

	return notes, nil, nil
}

// findAssetURL finds the browser download URL for an asset by its name
// within a list of GhUpMetaAsset.
func (gumf *GhUpMetaFetcher) findAssetURL(assets []GhUpMetaAsset, name string) *string {
	for _, asset := range assets {
		if asset.Name == name {
			return &asset.BrowserDownloadURL
		}
	}
	return nil
}

func main() {
	// Create an instance of GhUpMetaFetcher for your repository
	// The variable name 'fetcher' is often used for objects that fetch data.
	fetcher := NewGhUpMetaFetcher("sbamboo", "go-update-test")

	// Fetch and process the releases to get UpMeta data
	results, err := fetcher.FetchUpMetaReleases()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	// Marshal and print the results as JSON
	jsonOutput, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Println("ERROR marshalling JSON:", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonOutput))
}
