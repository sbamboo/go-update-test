package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// GhUpMetaAsset represents a release asset from the GitHub API.
type GhUpMetaAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

// GhUpMetaRelease represents a GitHub release with relevant fields.
type GhUpMetaRelease struct {
	TagName    string          `json:"tag_name"`
	Body       string          `json:"body"`
	Assets     []GhUpMetaAsset `json:"assets"`
	ReleasedAt string          `json:"published_at"`
}

// UpMeta represents the structured update metadata.
type UpMeta struct {
	UpMetaVer string `json:"__upmeta__"`
	Format    int    `json:"format"`
	Uind      int    `json:"uind"`
	Semver    string `json:"semver"`
	Channel   string `json:"channel"`

	Sources map[string]struct {
		URL            string  `json:"url,omitempty"`
		Checksum       string  `json:"checksum"`
		Signature      *string `json:"signature,omitempty"`      // Content of the .sig file
		IsPatch        bool    `json:"is_patch"`                 // True if an associated patch exists
		PatchFor       *int    `json:"patch_for,omitempty"`      // From patch filename
		PatchChecksum  *string `json:"patch_checksum,omitempty"` // Checksum of the patch file
		PatchSignature *string `json:"patch_signature,omitempty"`
		PatchURL       *string `json:"patch_url,omitempty"`
		Filename       string  `json:"filename,omitempty"` // Original filename from GitHub asset
	} `json:"sources"`
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

// fetchFileContent fetches the content of a file from a given URL.
func (gumf *GhUpMetaFetcher) fetchFileContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch content from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP status %d fetching %s: %s", resp.StatusCode, url, string(bodyBytes))
	}

	contentBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read content from %s: %w", url, err)
	}

	return string(contentBytes), nil
}

// FetchUpMetaReleases fetches releases from GitHub and extracts metadata
// based on tag names and asset properties.
func (gumf *GhUpMetaFetcher) FetchUpMetaReleases() ([]map[string]interface{}, error) {
	releases, err := gumf.fetchReleases()
	if err != nil {
		return nil, fmt.Errorf("error fetching releases: %w", err)
	}

	var results []map[string]interface{}

	for _, rel := range releases {
		upmeta, err := gumf.parseTagForUpMeta(rel.TagName)
		if err != nil {
			fmt.Printf("ERROR parsing tag %s: %v\n", rel.TagName, err)
			continue
		}

		notes := strings.TrimSpace(strings.SplitN(rel.Body, "<details>", 2)[0])

		obj := map[string]interface{}{
			"tag":      rel.TagName,
			"notes":    notes,
			"released": rel.ReleasedAt,
		}

		if upmeta != nil {
			upmeta.Sources = make(map[string]struct {
				URL            string  `json:"url,omitempty"`
				Checksum       string  `json:"checksum"`
				Signature      *string `json:"signature,omitempty"`
				IsPatch        bool    `json:"is_patch"`
				PatchFor       *int    `json:"patch_for,omitempty"`
				PatchChecksum  *string `json:"patch_checksum,omitempty"`
				PatchSignature *string `json:"patch_signature,omitempty"`
				PatchURL       *string `json:"patch_url,omitempty"`
				Filename       string  `json:"filename,omitempty"`
			})

			assetMap := make(map[string]GhUpMetaAsset)
			for _, asset := range rel.Assets {
				assetMap[asset.Name] = asset
			}

			// Process main executable assets
			for _, asset := range rel.Assets {
				// Skip signature and patch files when iterating for main assets
				if strings.HasSuffix(asset.Name, ".sig") || strings.Contains(asset.Name, ".patch") {
					continue
				}

				// Derive the source key (platform-arch)
				sourceKey := extractPlatformArch(asset.Name)
				if sourceKey == "" {
					fmt.Printf("WARNING: Could not determine platform-arch for asset '%s'. Skipping.\n", asset.Name)
					continue
				}

				source := struct {
					URL            string  `json:"url,omitempty"`
					Checksum       string  `json:"checksum"`
					Signature      *string `json:"signature,omitempty"`
					IsPatch        bool    `json:"is_patch"`
					PatchFor       *int    `json:"patch_for,omitempty"`
					PatchChecksum  *string `json:"patch_checksum,omitempty"`
					PatchSignature *string `json:"patch_signature,omitempty"`
					PatchURL       *string `json:"patch_url,omitempty"`
					Filename       string  `json:"filename,omitempty"`
				}{
					URL:      asset.BrowserDownloadURL,
					Filename: asset.Name,
					// Initialize patch fields to null/default
					IsPatch:        false,
					PatchFor:       nil,
					PatchChecksum:  nil,
					PatchSignature: nil,
					PatchURL:       nil,
				}

				// Extract checksum from digest
				if digestParts := strings.SplitN(asset.Digest, ":", 2); len(digestParts) == 2 && digestParts[0] == "sha256" {
					source.Checksum = digestParts[1]
				} else {
					fmt.Printf("WARNING: Unexpected digest format for asset %s: %s\n", asset.Name, asset.Digest)
					source.Checksum = ""
				}

				// Fetch signature content
				sigAssetName := asset.Name + ".sig"
				if sigAsset, ok := assetMap[sigAssetName]; ok {
					sigContent, err := gumf.fetchFileContent(sigAsset.BrowserDownloadURL)
					if err != nil {
						fmt.Printf("ERROR fetching signature for %s: %v\n", asset.Name, err)
						// Decide whether to skip or set signature to nil on error
						source.Signature = nil
					} else {
						source.Signature = &sigContent
					}
				}

				// Check for associated patch file
				filenameNoExt := strings.TrimSuffix(asset.Name, getFileExtension(asset.Name))
				patchRegex := regexp.MustCompile(
					`^` + regexp.QuoteMeta(filenameNoExt) + `_(\d+)t(\d+)\.patch$`,
				)

				for _, patchAssetCandidate := range rel.Assets {
					if strings.HasSuffix(patchAssetCandidate.Name, ".patch") {
						matches := patchRegex.FindStringSubmatch(patchAssetCandidate.Name)
						if len(matches) == 3 {
							source.IsPatch = true
							source.PatchURL = &patchAssetCandidate.BrowserDownloadURL

							if digestParts := strings.SplitN(
								patchAssetCandidate.Digest,
								":",
								2,
							); len(digestParts) == 2 && digestParts[0] == "sha256" {
								patchChecksum := digestParts[1]
								source.PatchChecksum = &patchChecksum
							}

							// Fetch patch signature content
							patchSigAssetName := patchAssetCandidate.Name + ".sig"
							if patchSigAsset, ok := assetMap[patchSigAssetName]; ok {
								patchSigContent, err := gumf.fetchFileContent(patchSigAsset.BrowserDownloadURL)
								if err != nil {
									fmt.Printf("ERROR fetching patch signature for %s: %v\n", patchAssetCandidate.Name, err)
									source.PatchSignature = nil
								} else {
									source.PatchSignature = &patchSigContent
								}
							}

							if patchForUind, err := strconv.Atoi(matches[1]); err == nil {
								source.PatchFor = &patchForUind
							}
							break
						}
					}
				}
				upmeta.Sources[sourceKey] = source
			}
			obj["upmeta"] = upmeta
		}
		results = append(results, obj)
	}
	return results, nil
}

// fetchReleases fetches raw GhUpMetaRelease data from the GitHub API.
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

// parseTagForUpMeta parses the tag name "ci-<channel>-<uind>-<semver>"
// to extract UpMeta fields.
func (gumf *GhUpMetaFetcher) parseTagForUpMeta(tagName string) (*UpMeta, error) {
	if !strings.HasPrefix(tagName, "ci-") {
		return nil, fmt.Errorf("tag name '%s' does not start with 'ci-'", tagName)
	}

	strippedTag := tagName[len("ci-"):] // Remove "ci-" prefix

	// Split from the right to easily get semver and uind
	// Example: "git.commit-5-0.0.0" -> ["git.commit-5", "0.0.0"]
	parts := strings.Split(strippedTag, "-")

	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid tag format for '%s': expected at least 3 parts after 'ci-' (channel-uind-semver)", tagName)
	}

	semver := parts[len(parts)-1]
	uindStr := parts[len(parts)-2]

	channelParts := parts[:len(parts)-2] // All parts before uind and semver
	channel := strings.Join(channelParts, "-")

	uind, err := strconv.Atoi(uindStr)
	if err != nil {
		return nil, fmt.Errorf("invalid uind '%s' in tag '%s': %w", uindStr, tagName, err)
	}

	return &UpMeta{
		UpMetaVer: "unknown", // Statically set as per requirement
		Format:    1,         // Example format version
		Uind:      uind,
		Semver:    semver,
		Channel:   channel,
	}, nil
}

// reverseString reverses a string.
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// extractPlatformArch parses a filename to extract the "<platform>-<arch>" part.
func extractPlatformArch(filename string) string {
	filenameNoExt := strings.TrimSuffix(filename, getFileExtension(filename))

	reversedFilename := reverseString(filenameNoExt)

	// We are looking for the pattern "arch-platform" in the reversed string.
	// We need to find the first '-' or '_' after the architecture.
	// Then the next '-' or '_' after the platform.

	var parts []string
	currentPart := ""
	delimiterCount := 0

	for _, r := range reversedFilename {
		if r == '-' || r == '_' {
			if currentPart != "" {
				parts = append(parts, currentPart)
				currentPart = ""
				delimiterCount++
				if delimiterCount == 2 {
					break // Found two delimiters, so we have the arch and platform parts
				}
			}
		} else {
			currentPart += string(r)
		}
	}
	if currentPart != "" { // Add the last part if string ends without a delimiter
		parts = append(parts, currentPart)
	}

	// We need at least two parts for "arch" and "platform"
	if len(parts) >= 2 {
		arch := reverseString(parts[0])     // First part found in reversed string is the architecture
		platform := reverseString(parts[1]) // Second part found is the platform

		// Reconstruct as "platform-arch"
		return fmt.Sprintf("%s-%s", platform, arch)
	}

	return "" // Could not parse platform-arch
}

// getFileExtension extracts the file extension from a filename.
func getFileExtension(filename string) string {
	dotIndex := strings.LastIndex(filename, ".")
	if dotIndex == -1 || dotIndex == len(filename)-1 {
		return ""
	}
	return filename[dotIndex:]
}

func main() {
	// Create an instance of GhUpMetaFetcher for your repository
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
