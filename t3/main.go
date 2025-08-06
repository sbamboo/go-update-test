package main

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/inconshreveable/go-update"

	_ "embed"
)

// App metadata injected at compile time
var (
	AppVersion    = "0.0.0"
	AppUIND       = "0"
	AppChannel    = "default"
	AppBuildTime  = "unknown"
	AppCommitHash = "unknown"
)

//go:embed public.pem
var appPublicKey []byte

// SourceInfo holds URLs for a specific OS/Architecture
type SourceInfo struct {
	IsPatch   bool    `json:"is_patch"`
	URL       string  `json:"url"`
	PatchURL  *string `json:"patch_url"` // Pointer to string to allow null
	PatchFor  *int    `json:"patch_for"` // Pointer to int to allow null
	Checksum  string  `json:"checksum"`
	Signature string  `json:"signature"`
}

type ReleaseInfo struct {
	UIND     int                   `json:"uind"`
	Semver   string                `json:"semver"`
	Released string                `json:"released"`
	Notes    string                `json:"notes"`
	Sources  map[string]SourceInfo `json:"sources"` // Map for platform-specific URLs
}

type DeployFile struct {
	Format   int                      `json:"format"`
	Channels map[string][]ReleaseInfo `json:"channels"`
}

const deployURL = "https://raw.githubusercontent.com/sbamboo/go-update-test/refs/heads/main/t3/deploy.json"

func main() {
	fmt.Println("--- Go Update CLI App ---")
	fmt.Printf("Version: %s (UIND: %s)\n", AppVersion, AppUIND)
	fmt.Printf("Channel: %s\n", AppChannel)
	fmt.Printf("Build Time: %s\n", AppBuildTime)
	fmt.Printf("Commit Hash: %s\n", AppCommitHash)
	fmt.Printf("Running on: %s-%s\n", runtime.GOOS, runtime.GOARCH) // Show current platform

	currentUIND, _ := strconv.Atoi(AppUIND)

	latestRelease, err := getLatestVersion(AppChannel)
	if err != nil {
		fmt.Printf("Error checking for updates: %v\n", err)
	} else if latestRelease != nil && latestRelease.UIND > currentUIND {
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
			if latestRelease == nil || latestRelease.UIND <= currentUIND {
				fmt.Println("No update available or you are already on the latest version.")
				continue
			}
			fmt.Printf("Attempting to update to version %s...\n", latestRelease.Semver)
			err := performUpdate(latestRelease, currentUIND)
			if err != nil {
				fmt.Printf("Update failed: %v\n", err)
				if rerr := update.RollbackError(err); rerr != nil {
					fmt.Printf("Failed to rollback from bad update: %v\n", rerr)
				}
			} else {
				fmt.Println("Update successful! Please restart the application.")
				break
			}
		} else {
			fmt.Printf("Switching to channel: %s\n", input)
			AppChannel = input // This doesn't change the compiled-in channel but affects the current session's update check
			latestRelease, err = getLatestVersion(AppChannel)
			if err != nil {
				fmt.Printf("Error checking for updates in channel '%s': %v\n", AppChannel, err)
			} else if latestRelease != nil && latestRelease.UIND > currentUIND {
				fmt.Printf("\n--- Update Available for Channel %s! ---\n", AppChannel)
				fmt.Printf("New Version: %s (UIND: %d)\n", latestRelease.Semver, latestRelease.UIND)
				fmt.Printf("Notes: %s\n", latestRelease.Notes)
				fmt.Println("-----------------------------------------\n")
			} else {
				fmt.Printf("No newer version available in channel '%s'.\n", AppChannel)
			}
		}
	}
}

func getLatestVersion(channel string) (*ReleaseInfo, error) {
	resp, err := http.Get(deployURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deploy.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch deploy.json, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read deploy.json response body: %w", err)
	}

	var deployFile DeployFile
	err = json.Unmarshal(body, &deployFile)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal deploy.json: %w", err)
	}

	releases, ok := deployFile.Channels[channel]
	if !ok || len(releases) == 0 {
		return nil, fmt.Errorf("no releases found for channel '%s'", channel)
	}

	var latest *ReleaseInfo
	for i := range releases {
		release := &releases[i]
		// Ensure the release has source info for the current platform
		platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
		if _, ok := release.Sources[platformKey]; ok {
			if latest == nil || release.UIND > latest.UIND {
				latest = release
			}
		} else {
			fmt.Printf("Skipping release %s (UIND %d) - no build found for %s-%s\n", release.Semver, release.UIND, runtime.GOOS, runtime.GOARCH)
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no compatible releases found for channel '%s' on %s-%s", channel, runtime.GOOS, runtime.GOARCH)
	}
	return latest, nil
}

func performUpdate(latestRelease *ReleaseInfo, currentUIND int) error {
	opts := update.Options{}

	// Set public key for signature verification
	err := opts.SetPublicKeyPEM(appPublicKey)
	if err != nil {
		return fmt.Errorf("failed to set public key: %w", err)
	}

	// Get platform-specific source URLs
	platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	latestPlatformRelease, ok := latestRelease.Sources[platformKey]
	if !ok {
		return fmt.Errorf("no update source found for current platform: %s", platformKey)
	}

	// Checksum
	checksum, err := hex.DecodeString(latestPlatformRelease.Checksum)
	if err != nil {
		return fmt.Errorf("failed to decode checksum: %w", err)
	}

	// Decode base64 signature
	signature, err := base64.StdEncoding.DecodeString(latestPlatformRelease.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	opts.Checksum = checksum
	opts.Signature = signature
	opts.Hash = crypto.SHA256                 // Default, but good to explicitly set
	opts.Verifier = update.NewECDSAVerifier() // Default, but good to explicitly set

	var updateReader io.Reader

	// Handle binary patching
	if latestPlatformRelease.IsPatch {
		if latestPlatformRelease.PatchURL == nil || *latestPlatformRelease.PatchURL == "" {
			fmt.Println("Warning: Release is marked as patch but no patch_url for current platform. Falling back to full update.")
			latestPlatformRelease.IsPatch = false // Force full update
		} else {
			//patchPath := []ReleaseInfo{*latestRelease} // Simplified: we only care about the latest patch

			// Check if the patch can be directly applied
			if latestPlatformRelease.PatchFor != nil && *latestPlatformRelease.PatchFor == currentUIND {
				// Direct patch path: current -> latest
			} else {
				// Try to find a multi-step patch path
				fmt.Println("Attempting to find a multi-step patch path...")
				// This is a simplified example. A real implementation would need to
				// fetch all releases in the channel to find intermediate patches.
				// For this example, we'll only support direct patches or full updates.
				fmt.Println("Multi-step patching not fully implemented in this example.")
				fmt.Println("Falling back to full update.")
				latestPlatformRelease.IsPatch = false // Force full update
			}
		}
	}

	if latestPlatformRelease.IsPatch && latestPlatformRelease.PatchURL != nil && *latestPlatformRelease.PatchURL != "" && *latestPlatformRelease.PatchFor == currentUIND {
		fmt.Printf("Downloading patch from: %s\n", *latestPlatformRelease.PatchURL)
		resp, err := http.Get(*latestPlatformRelease.PatchURL)
		if err != nil {
			return fmt.Errorf("failed to download patch: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to download patch, status code: %d", resp.StatusCode)
		}
		updateReader = resp.Body
		opts.Patcher = update.NewBSDiffPatcher()
	} else {
		if latestPlatformRelease.PatchURL != nil && *latestPlatformRelease.PatchURL != "" && *latestPlatformRelease.PatchFor == currentUIND {
			fmt.Printf("Warning: Patch URL was invalid or the updates patch was not applicable for current UIND %d. Falling back to full binary.\n", currentUIND)
		}

		fmt.Printf("Downloading full binary from: %s\n", latestPlatformRelease.URL)
		resp, err := http.Get(latestPlatformRelease.URL)
		if err != nil {
			return fmt.Errorf("failed to download full binary: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to download full binary, status code: %d", resp.StatusCode)
		}
		updateReader = resp.Body
	}

	// Create a buffer to store the update content for checksum verification
	updateContent := new(bytes.Buffer)
	teeReader := io.TeeReader(updateReader, updateContent)

	err = update.Apply(teeReader, opts)
	if err != nil {
		return fmt.Errorf("failed to apply update: %w", err)
	}

	return nil
}
