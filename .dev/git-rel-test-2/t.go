package main

import (
	"bufio"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/inconshreveable/go-update"
	"gopkg.in/yaml.v3"

	_ "embed"
)

// -- Application Metadata --

// App metadata injected at compile time (these will be passed to NetUpdater)
var (
	AppVersion      = "0.0.0"
	AppUIND         = "0"
	AppChannel      = "default"
	AppBuildTime    = "unknown"
	AppCommitHash   = "unknown"
	AppDeployURL    string
	AppGhUpMetaRepo = "" // If not provided this will be cast to *string nil later
)

//go:embed signing/public.pem
var appPublicKey []byte

// --- GitHub UpMeta Fetcher Structures and Methods (for asset-based parsing: "git." channels) ---

// GhUpMetaAsset represents a release asset from the GitHub API.
type GhUpMetaAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"` // Used for checksum extraction
}

// GhUpMetaReleaseAssets represents a GitHub release with relevant fields for asset parsing.
type GhUpMetaReleaseAssets struct {
	TagName    string          `json:"tag_name"`
	Body       string          `json:"body"`
	Assets     []GhUpMetaAsset `json:"assets"`
	ReleasedAt string          `json:"published_at"`
}

// UpMetaAssets represents the structured update metadata derived from asset names.
type UpMetaAssets struct {
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

// GhUpMetaFetcherAssets encapsulates the logic for fetching and processing
// GitHub releases to extract update metadata (`UpMetaAssets`) by inspecting assets.
type GhUpMetaFetcherAssets struct {
	Owner string
	Repo  string
}

// NewGhUpMetaFetcherAssets creates a new instance of GhUpMetaFetcherAssets.
func NewGhUpMetaFetcherAssets(owner, repo string) *GhUpMetaFetcherAssets {
	return &GhUpMetaFetcherAssets{
		Owner: owner,
		Repo:  repo,
	}
}

// fetchFileContent fetches the content of a file from a given URL.
func (gumf *GhUpMetaFetcherAssets) fetchFileContent(url string) (string, error) {
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
// based on tag names and asset properties for "git." channels.
func (gumf *GhUpMetaFetcherAssets) FetchUpMetaReleases() ([]map[string]interface{}, error) {
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
					source.Checksum = "" // Or handle as an error
				}

				// Fetch signature content
				sigAssetName := asset.Name + ".sig"
				if sigAsset, ok := assetMap[sigAssetName]; ok {
					sigContent, err := gumf.fetchFileContent(sigAsset.BrowserDownloadURL)
					if err != nil {
						fmt.Printf("ERROR fetching signature for %s: %v\n", asset.Name, err)
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

// fetchReleases fetches raw GhUpMetaReleaseAssets data from the GitHub API.
func (gumf *GhUpMetaFetcherAssets) fetchReleases() ([]GhUpMetaReleaseAssets, error) {
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

	var releases []GhUpMetaReleaseAssets
	err = json.Unmarshal(bodyBytes, &releases)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	return releases, nil
}

// parseTagForUpMeta parses the tag name "ci-<channel>-<uind>-<semver>"
// to extract UpMetaAssets fields.
func (gumf *GhUpMetaFetcherAssets) parseTagForUpMeta(tagName string) (*UpMetaAssets, error) {
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

	return &UpMetaAssets{
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
// Example: "mycli_linux-amd64" -> "linux-amd64"
// Example: "mycli_v1.0.0_windows-arm64.exe" -> "windows-arm64"
func extractPlatformArch(filename string) string {
	filenameNoExt := strings.TrimSuffix(filename, getFileExtension(filename))

	// Attempt to find patterns like os-arch or os_arch
	// This regex looks for:
	// - a word character (like a letter or number)
	// - followed by either a '-' or '_'
	// - followed by another word character
	// - at the end of the string (before extension)
	// This helps in finding "linux-amd64" or "windows_arm64"
	re := regexp.MustCompile(`([a-zA-Z0-9]+)[-_]([a-zA-Z0-9]+)$`)
	matches := re.FindStringSubmatch(filenameNoExt)
	if len(matches) == 3 {
		// matches[1] is platform, matches[2] is arch
		return fmt.Sprintf("%s-%s", matches[1], matches[2])
	}

	// Fallback to the original, more complex logic if the simple regex doesn't match
	// The original logic assumes platform-arch is at the end of the base filename
	reversedFilename := reverseString(filenameNoExt)

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
					break
				}
			}
		} else {
			currentPart += string(r)
		}
	}
	if currentPart != "" {
		parts = append(parts, currentPart)
	}

	if len(parts) >= 2 {
		arch := reverseString(parts[0])
		platform := reverseString(parts[1])
		return fmt.Sprintf("%s-%s", platform, arch)
	}

	return ""
}

// getFileExtension extracts the file extension from a filename.
func getFileExtension(filename string) string {
	dotIndex := strings.LastIndex(filename, ".")
	if dotIndex == -1 || dotIndex == len(filename)-1 {
		return ""
	}
	return filename[dotIndex:]
}

// --- GitHub UpMeta Fetcher Structures and Methods (for release body parsing: "ugit." channels) ---

// GhUpMetaReleaseBody represents a GitHub release with fields relevant for UpMetaBody processing.
type GhUpMetaReleaseBody struct {
	TagName  string          `json:"tag_name"`
	Body     string          `json:"body"`
	Assets   []GhUpMetaAsset `json:"assets"` // Re-using GhUpMetaAsset from above
	Released string          `json:"published_at"`
}

// UpMetaBody represents the __upmeta__ YAML structure found in GitHub release bodies.
type UpMetaBody struct {
	UpMetaVer string `yaml:"__upmeta__" json:"__upmeta__"`
	Format    int    `yaml:"format" json:"format"`
	Uind      int    `yaml:"uind" json:"uind"`
	Semver    string `yaml:"semver" json:"semver"`
	Channel   string `yaml:"channel" json:"channel"`

	Sources map[string]struct {
		URL            string  `yaml:"url,omitempty" json:"url"`
		Checksum       string  `yaml:"checksum" json:"checksum"`
		Signature      string  `yaml:"signature" json:"signature"`
		IsPatch        bool    `yaml:"is_patch" json:"is_patch"`
		PatchFor       *int    `yaml:"patch_for" json:"patch_for"`
		PatchChecksum  *string `yaml:"patch_checksum" json:"patch_checksum"`
		PatchSignature *string `yaml:"patch_signature" json:"patch_signature"`
		PatchURL       *string `yaml:"patch_url,omitempty" json:"patch_url"`
		Filename       string  `yaml:"filename,omitempty" json:"filename"`
		PatchAsset     *string `yaml:"patch_asset,omitempty" json:"patch_asset"`
	} `yaml:"sources" json:"sources"`
}

// GhUpMetaFetcherBody encapsulates the logic for fetching and processing
// GitHub releases to extract update metadata (`UpMetaBody`) from the release body YAML.
type GhUpMetaFetcherBody struct {
	Owner string
	Repo  string
}

// NewGhUpMetaFetcherBody creates a new instance of GhUpMetaFetcherBody.
func NewGhUpMetaFetcherBody(owner, repo string) *GhUpMetaFetcherBody {
	return &GhUpMetaFetcherBody{
		Owner: owner,
		Repo:  repo,
	}
}

// FetchUpMetaReleases fetches releases from GitHub, parses their bodies
// for UpMetaBody, and attaches asset URLs, returning processed release data for "ugit." channels.
func (gum *GhUpMetaFetcherBody) FetchUpMetaReleases() ([]map[string]interface{}, error) {
	releases, err := gum.fetchReleases()
	if err != nil {
		return nil, fmt.Errorf("error fetching releases: %w", err)
	}

	var results []map[string]interface{}

	for _, rel := range releases {
		notes, upmeta, err := gum.parseReleaseBody(rel.Body)
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
				if url := gum.findAssetURL(rel.Assets, source.Filename); url != nil {
					source.URL = *url
				}

				if source.PatchAsset != nil {
					if patchURL := gum.findAssetURL(rel.Assets, *source.PatchAsset); patchURL != nil {
						source.PatchURL = patchURL
					}
				} else {
					source.PatchURL = nil // Ensure nil if patch_asset is not specified
				}

				upmeta.Sources[key] = source
			}

			obj["upmeta"] = upmeta
		}

		results = append(results, obj)
	}
	return results, nil
}

// fetchReleases fetches raw GhUpMetaReleaseBody data from the GitHub API for the
// configured owner and repository.
func (gum *GhUpMetaFetcherBody) fetchReleases() ([]GhUpMetaReleaseBody, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", gum.Owner, gum.Repo)
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

	var releases []GhUpMetaReleaseBody
	err = json.Unmarshal(bodyBytes, &releases)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	return releases, nil
}

// parseReleaseBody extracts release notes and an optional UpMetaBody struct
// from a GitHub release body string.
func (gum *GhUpMetaFetcherBody) parseReleaseBody(body string) (string, *UpMetaBody, error) {
	// Extract the notes: everything before the first <details> tag
	notes := strings.TrimSpace(strings.SplitN(body, "<details>", 2)[0])

	// Match all ```yaml ... blocks
	codeBlockRe := regexp.MustCompile("(?s)```yaml\\s*\n(.*?)```")
	matches := codeBlockRe.FindAllStringSubmatch(body, -1)

	if matches == nil || len(matches) == 0 {
		return notes, nil, nil
	}

	for _, match := range matches {
		yamlContent := strings.TrimSpace(match[1])

		if strings.Contains(yamlContent, "__upmeta__") {
			var upmeta UpMetaBody
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
func (gum *GhUpMetaFetcherBody) findAssetURL(assets []GhUpMetaAsset, name string) *string {
	for _, asset := range assets {
		if asset.Name == name {
			return &asset.BrowserDownloadURL
		}
	}
	return nil
}

// --- Main NetUpdater structures and methods ---

// NetUpSourceInfo holds URLs for a specific OS/Architecture within a release.
type NetUpSourceInfo struct {
	IsPatch        bool    `json:"is_patch"`
	URL            string  `json:"url"`
	PatchURL       *string `json:"patch_url"`       // Pointer to string to allow null
	PatchFor       *int    `json:"patch_for"`       // Pointer to int to allow null
	Checksum       string  `json:"checksum"`        // Checksum of the full binary
	Signature      *string `json:"signature"`       // Signature of the full binary (now pointer)
	PatchChecksum  *string `json:"patch_checksum"`  // Checksum of the patch file, pointer to allow null
	PatchSignature *string `json:"patch_signature"` // Signature of the patch file, pointer to allow null
}

// NetUpReleaseInfo contains details about a specific software release.
type NetUpReleaseInfo struct {
	UIND     int                        `json:"uind"`
	Semver   string                     `json:"semver"`
	Released string                     `json:"released"`
	Notes    string                     `json:"notes"`
	Sources  map[string]NetUpSourceInfo `json:"sources"` // Map for platform-specific URLs
}

// NetUpDeployFile represents the structure of the deploy.json file.
type NetUpDeployFile struct {
	Format   int                           `json:"format"`
	Channels map[string][]NetUpReleaseInfo `json:"channels"`
}

// NetUpdater provides methods for checking and applying updates from a remote source.
type NetUpdater struct {
	SemVer           string
	UIND             int
	Channel          string
	Released         string
	Commit           string
	PublicKeyPEM     []byte
	DeployURL        string
	GithubUpMetaRepo *string                // New field for GitHub repo (e.g., "owner/repo")
	Target           string                 // e.g., "linux-amd64"
	ghMetaFetcherBdy *GhUpMetaFetcherBody   // Internal instance for GitHub fetching (body parsing)
	ghMetaFetcherAst *GhUpMetaFetcherAssets // Internal instance for GitHub fetching (asset parsing)
}

// NewNetUpdater creates and initializes a new NetUpdater instance.
func NewNetUpdater(semver, uindStr, channel, released, commit, deployURL string, githubUpMetaRepo *string, publicKey []byte, target string) (*NetUpdater, error) {
	currentUIND, err := strconv.Atoi(uindStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AppUIND: %w", err)
	}

	nu := &NetUpdater{
		SemVer:           semver,
		UIND:             currentUIND,
		Channel:          channel,
		Released:         released,
		Commit:           commit,
		PublicKeyPEM:     publicKey,
		DeployURL:        deployURL,
		GithubUpMetaRepo: githubUpMetaRepo,
		Target:           target,
	}

	if githubUpMetaRepo != nil && strings.Contains(*githubUpMetaRepo, "/") {
		parts := strings.SplitN(*githubUpMetaRepo, "/", 2)
		if len(parts) == 2 {
			nu.ghMetaFetcherBdy = NewGhUpMetaFetcherBody(parts[0], parts[1])
			nu.ghMetaFetcherAst = NewGhUpMetaFetcherAssets(parts[0], parts[1])
		}
	}

	return nu, nil
}

// GetLatestVersion fetches the deploy file or GitHub releases and determines the latest compatible release
// for the updater's current channel and platform.
func (nu *NetUpdater) GetLatestVersion() (*NetUpReleaseInfo, error) {
	if strings.HasPrefix(nu.Channel, "ugit.") {
		if nu.ghMetaFetcherBdy == nil {
			return nil, fmt.Errorf("github update meta repo not configured for 'ugit.' channel")
		}
		return nu.getLatestVersionFromGitHubBody()
	} else if strings.HasPrefix(nu.Channel, "git.") {
		if nu.ghMetaFetcherAst == nil {
			return nil, fmt.Errorf("github update meta repo not configured for 'git.' channel")
		}
		return nu.getLatestVersionFromGitHubAssets()
	} else {
		return nu.getLatestVersionFromJsonDeploy()
	}
}

// getLatestVersionFromJsonDeploy fetches update metadata from a deploy.json file.
func (nu *NetUpdater) getLatestVersionFromJsonDeploy() (*NetUpReleaseInfo, error) {
	fmt.Println("Fetching deploy.json from:", nu.DeployURL)
	resp, err := http.Get(nu.DeployURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deploy.json from %s: %w", nu.DeployURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch deploy.json, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read deploy.json response body: %w", err)
	}

	var deployFile NetUpDeployFile
	err = json.Unmarshal(body, &deployFile)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal deploy.json: %w", err)
	}

	releases, ok := deployFile.Channels[nu.Channel]
	if !ok || len(releases) == 0 {
		return nil, fmt.Errorf("no releases found for channel '%s'", nu.Channel)
	}

	var latest *NetUpReleaseInfo
	for i := range releases {
		release := &releases[i]
		// Ensure the release has source info for the current platform
		if _, ok := release.Sources[nu.Target]; ok {
			if latest == nil || release.UIND > latest.UIND {
				latest = release
			}
		} else {
			fmt.Printf("Skipping release %s (UIND %d) - no build found for %s\n", release.Semver, release.UIND, nu.Target)
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no compatible releases found for channel '%s' on %s", nu.Channel, nu.Target)
	}
	return latest, nil
}

// getLatestVersionFromGitHubBody fetches update metadata from GitHub releases by parsing release bodies.
func (nu *NetUpdater) getLatestVersionFromGitHubBody() (*NetUpReleaseInfo, error) {
	ghReleases, err := nu.ghMetaFetcherBdy.FetchUpMetaReleases()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub releases (body parse): %w", err)
	}

	var latestUpMeta *UpMetaBody
	var latestNotes string
	var latestReleased string

	for _, rel := range ghReleases {
		upmetaVal, ok := rel["upmeta"]
		if !ok {
			continue // No upmeta found for this release
		}
		upmeta, ok := upmetaVal.(*UpMetaBody)
		if !ok {
			continue // Type assertion failed
		}

		// Filter by channel
		if upmeta.Channel != nu.Channel {
			continue
		}

		// Check if source exists for current platform
		if _, ok := upmeta.Sources[nu.Target]; !ok {
			fmt.Printf("Skipping GitHub release %s (UIND %d) - no build found for %s\n", upmeta.Semver, upmeta.Uind, nu.Target)
			continue
		}

		if latestUpMeta == nil || upmeta.Uind > latestUpMeta.Uind {
			latestUpMeta = upmeta
			latestNotes = rel["notes"].(string)
			latestReleased = rel["released"].(string)
		}
	}

	if latestUpMeta == nil {
		return nil, fmt.Errorf("no compatible GitHub releases found for channel '%s' on %s (body parse)", nu.Channel, nu.Target)
	}

	// Transform UpMetaBody to NetUpReleaseInfo
	sources := make(map[string]NetUpSourceInfo)
	for platform, source := range latestUpMeta.Sources {
		// Convert string signature to *string
		var sig *string
		if source.Signature != "" {
			s := source.Signature
			sig = &s
		}
		sources[platform] = NetUpSourceInfo{
			IsPatch:        source.IsPatch,
			URL:            source.URL,
			PatchURL:       source.PatchURL,
			PatchFor:       source.PatchFor,
			Checksum:       source.Checksum,
			Signature:      sig, // Now a pointer
			PatchChecksum:  source.PatchChecksum,
			PatchSignature: source.PatchSignature,
		}
	}

	return &NetUpReleaseInfo{
		UIND:     latestUpMeta.Uind,
		Semver:   latestUpMeta.Semver,
		Released: latestReleased,
		Notes:    latestNotes,
		Sources:  sources,
	}, nil
}

// getLatestVersionFromGitHubAssets fetches update metadata from GitHub releases by parsing asset names and tags.
func (nu *NetUpdater) getLatestVersionFromGitHubAssets() (*NetUpReleaseInfo, error) {
	ghReleases, err := nu.ghMetaFetcherAst.FetchUpMetaReleases()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub releases (asset parse): %w", err)
	}

	var latestUpMeta *UpMetaAssets
	var latestNotes string
	var latestReleased string

	for _, rel := range ghReleases {
		upmetaVal, ok := rel["upmeta"]
		if !ok {
			continue // No upmeta found for this release
		}
		upmeta, ok := upmetaVal.(*UpMetaAssets)
		if !ok {
			continue // Type assertion failed
		}

		// Filter by channel (from tag)
		if upmeta.Channel != strings.TrimPrefix(nu.Channel, "git.") { // Compare with "git.xyz" vs "xyz"
			continue
		}

		// Check if source exists for current platform
		if _, ok := upmeta.Sources[nu.Target]; !ok {
			fmt.Printf("Skipping GitHub release %s (UIND %d) - no build found for %s\n", upmeta.Semver, upmeta.Uind, nu.Target)
			continue
		}

		if latestUpMeta == nil || upmeta.Uind > latestUpMeta.Uind {
			latestUpMeta = upmeta
			latestNotes = rel["notes"].(string)
			latestReleased = rel["released"].(string)
		}
	}

	if latestUpMeta == nil {
		return nil, fmt.Errorf("no compatible GitHub releases found for channel '%s' on %s (asset parse)", nu.Channel, nu.Target)
	}

	// Transform UpMetaAssets to NetUpReleaseInfo
	sources := make(map[string]NetUpSourceInfo)
	for platform, source := range latestUpMeta.Sources {
		sources[platform] = NetUpSourceInfo{
			IsPatch:        source.IsPatch,
			URL:            source.URL,
			PatchURL:       source.PatchURL,
			PatchFor:       source.PatchFor,
			Checksum:       source.Checksum,
			Signature:      source.Signature,
			PatchChecksum:  source.PatchChecksum,
			PatchSignature: source.PatchSignature,
		}
	}

	return &NetUpReleaseInfo{
		UIND:     latestUpMeta.Uind,
		Semver:   latestUpMeta.Semver,
		Released: latestReleased,
		Notes:    latestNotes,
		Sources:  sources,
	}, nil
}

// PerformUpdate downloads and applies the specified release. It attempts a patch update
// if applicable, otherwise a full binary update.
func (nu *NetUpdater) PerformUpdate(latestRelease *NetUpReleaseInfo) error {
	opts := update.Options{}

	// Set public key for signature verification
	err := opts.SetPublicKeyPEM(nu.PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to set public key: %w", err)
	}

	// Get platform-specific source URLs
	latestPlatformRelease, ok := latestRelease.Sources[nu.Target]
	if !ok {
		return fmt.Errorf("no update source found for current platform: %s", nu.Target)
	}

	opts.Hash = crypto.SHA256                 // Default, but good to explicitly set
	opts.Verifier = update.NewECDSAVerifier() // Default, but good to explicitly set

	var downloadURL string
	var expectedChecksum []byte
	var expectedSignature []byte
	isPatchAttempt := false

	// Determine if we should attempt a patch update
	shouldAttemptPatch := latestPlatformRelease.IsPatch &&
		latestPlatformRelease.PatchURL != nil && *latestPlatformRelease.PatchURL != "" &&
		latestPlatformRelease.PatchFor != nil &&
		latestPlatformRelease.PatchChecksum != nil && *latestPlatformRelease.PatchChecksum != "" &&
		latestPlatformRelease.PatchSignature != nil && *latestPlatformRelease.PatchSignature != ""

	if shouldAttemptPatch {
		// Is the patch for us?
		if *latestPlatformRelease.PatchFor == nu.UIND {
			fmt.Printf("Attempting to download and apply patch from: %s\n", *latestPlatformRelease.PatchURL)
			downloadURL = *latestPlatformRelease.PatchURL
			opts.Patcher = update.NewBSDiffPatcher()

			// Set checksum and signature for the patch file
			expectedChecksum, err = hex.DecodeString(*latestPlatformRelease.PatchChecksum)
			if err != nil {
				return fmt.Errorf("failed to decode patch checksum: %w", err)
			}
			if latestPlatformRelease.PatchSignature != nil { // Check if signature is present
				expectedSignature, err = base64.StdEncoding.DecodeString(*latestPlatformRelease.PatchSignature)
				if err != nil {
					return fmt.Errorf("failed to decode patch signature: %w", err)
				}
			} else {
				// Handle case where patch signature is missing (e.g., from asset-based fetcher on error)
				fmt.Println("WARNING: Patch signature is missing. Update might fail if verification is strict.")
				expectedSignature = nil // Set to nil if not present, update library should handle
			}
			isPatchAttempt = true
		} else {
			// Warn the user that the patch is not for the current UIND and fallback to a full update
			fmt.Printf("Warning: Patch is for UIND %d, but current UIND is %d. Falling back to full update.\n", *latestPlatformRelease.PatchFor, nu.UIND)
			shouldAttemptPatch = false // Force fallback
		}
	}

	if !isPatchAttempt { // If we didn't attempt a patch, or if the patch attempt failed/was skipped
		if latestPlatformRelease.IsPatch {
			if latestPlatformRelease.PatchURL == nil || *latestPlatformRelease.PatchURL == "" {
				fmt.Println("Warning: Release is marked as patch but no patch_url for current platform. Falling back to full update.")
			} else if latestPlatformRelease.PatchFor == nil || *latestPlatformRelease.PatchFor != nu.UIND {
				// This case is already covered above, but kept for clarity if logic changes.
				// It implies shouldAttemptPatch was false because PatchFor didn't match.
			} else if latestPlatformRelease.PatchChecksum == nil || latestPlatformRelease.PatchSignature == nil { // Missing patch checksum or signature
				fmt.Println("Warning: Patch is available but missing checksum/signature. Falling back to full update.")
			}
		}

		fmt.Printf("Downloading full binary from: %s\n", latestPlatformRelease.URL)
		downloadURL = latestPlatformRelease.URL
		opts.Patcher = nil // No patcher needed for full binary update

		// Set checksum and signature for the full binary
		expectedChecksum, err = hex.DecodeString(latestPlatformRelease.Checksum)
		if err != nil {
			return fmt.Errorf("failed to decode full binary checksum: %w", err)
		}
		if latestPlatformRelease.Signature != nil { // Check if signature is present
			expectedSignature, err = base64.StdEncoding.DecodeString(*latestPlatformRelease.Signature)
			if err != nil {
				return fmt.Errorf("failed to decode full binary signature: %w", err)
			}
		} else {
			fmt.Println("WARNING: Main binary signature is missing. Update might fail if verification is strict.")
			expectedSignature = nil
		}
	}

	// Assign the derived checksum and signature to opts
	opts.Checksum = expectedChecksum
	opts.Signature = expectedSignature

	// Perform the HTTP GET request
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update from %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download update from %s, status code: %d", downloadURL, resp.StatusCode)
	}

	err = update.Apply(resp.Body, opts)
	if err != nil {
		return fmt.Errorf("failed to apply update: %w", err)
	}

	fmt.Println("Update applied successfully!")
	return nil
}

// --- Main application logic ---

func main() {
	var _appGhUpMetaRepo *string
	if AppGhUpMetaRepo != "" {
		_appGhUpMetaRepo = &AppGhUpMetaRepo
	} else {
		_appGhUpMetaRepo = nil
	}
	// Initialize the NetUpdater with app details and the deployment URL
	updater, err := NewNetUpdater(
		AppVersion,
		AppUIND,
		AppChannel,
		AppBuildTime,
		AppCommitHash,
		AppDeployURL,
		_appGhUpMetaRepo,
		appPublicKey,
		fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH),
	)
	if err != nil {
		fmt.Printf("Failed to initialize updater: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("--- Go Update CLI App ---")
	fmt.Printf("Version: %s (UIND: %d)\n", updater.SemVer, updater.UIND)
	fmt.Printf("Channel: %s\n", updater.Channel)
	fmt.Printf("Build Time: %s\n", updater.Released)
	fmt.Printf("Commit Hash: %s\n", updater.Commit)
	fmt.Printf("Running on: %s\n", updater.Target)
	if updater.GithubUpMetaRepo != nil {
		fmt.Printf("GitHub Repo: %s\n", *updater.GithubUpMetaRepo)
	}

	// This initial check determines if an update is available for the *default* channel
	// or the channel initially set.
	latestRelease, err := updater.GetLatestVersion()
	if err != nil {
		fmt.Printf("Error checking for updates: %v\n", err)
	} else if latestRelease != nil && latestRelease.UIND > updater.UIND {
		fmt.Printf("\n--- Update Available! ---\n")
		fmt.Printf("New Version: %s (UIND: %d)\n", latestRelease.Semver, latestRelease.UIND)
		fmt.Printf("Notes: %s\n", latestRelease.Notes)
		fmt.Println("-------------------------\n")
	} else {
		fmt.Println("You are running the latest version for your channel.")
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter channel name, 'update', or 'exit': ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "exit" {
			break
		}

		if input == "update" {
			if latestRelease == nil || latestRelease.UIND <= updater.UIND {
				fmt.Println("No update available or you are already on the latest version.")
				continue
			}
			fmt.Printf("Attempting to update to version %s...\n", latestRelease.Semver)
			err := updater.PerformUpdate(latestRelease)
			if err != nil {
				fmt.Printf("Update failed: %v\n", err)
				if rerr := update.RollbackError(err); rerr != nil {
					fmt.Printf("Failed to rollback from bad update: %v\n", rerr)
				}
			} else {
				fmt.Println("Update successful! Please restart the application.")
				// After a successful update, the UIND of the running binary is still the old one.
				// For demonstration, we could theoretically update updater.UIND and updater.SemVer
				// but in a real app, a restart is almost always required.
				break // Exit after successful update to encourage restart
			}
		} else {
			// Update the updater's channel property for the current session
			updater.Channel = input
			fmt.Printf("Switching to channel: %s\n", updater.Channel)
			// Re-check for the latest release in the newly set channel
			latestRelease, err = updater.GetLatestVersion()
			if err != nil {
				fmt.Printf("Error checking for updates in channel '%s': %v\n", updater.Channel, err)
			} else if latestRelease != nil && latestRelease.UIND > updater.UIND {
				fmt.Printf("\n--- Update Available for Channel %s! ---\n", updater.Channel)
				fmt.Printf("New Version: %s (UIND: %d)\n", latestRelease.Semver, latestRelease.UIND)
				fmt.Printf("Notes: %s\n", latestRelease.Notes)
				fmt.Println("-----------------------------------------\n")
			} else {
				fmt.Printf("No newer version available in channel '%s'.\n", updater.Channel)
			}
		}
	}
}
