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
	IsPatch        bool    `json:"is_patch"`
	URL            string  `json:"url"`
	PatchURL       *string `json:"patch_url"`       // Pointer to string to allow null
	PatchFor       *int    `json:"patch_for"`       // Pointer to int to allow null
	Checksum       string  `json:"checksum"`        // Checksum of the full binary
	Signature      string  `json:"signature"`       // Signature of the full binary
	PatchChecksum  *string `json:"patch_checksum"`  // Checksum of the patch file, pointer to allow null
	PatchSignature *string `json:"patch_signature"` // Signature of the patch file, pointer to allow null
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

	opts.Hash = crypto.SHA256                 // Default, but good to explicitly set
	opts.Verifier = update.NewECDSAVerifier() // Default, but good to explicitly set

	var downloadURL string
	var expectedChecksum []byte
	var expectedSignature []byte

	// Determine if we should attempt a patch update
	shouldAttemptPatch := latestPlatformRelease.IsPatch &&
		latestPlatformRelease.PatchURL != nil && *latestPlatformRelease.PatchURL != "" &&
		latestPlatformRelease.PatchFor != nil &&
		latestPlatformRelease.PatchChecksum != nil && *latestPlatformRelease.PatchChecksum != "" &&
		latestPlatformRelease.PatchSignature != nil && *latestPlatformRelease.PatchSignature != ""

	if shouldAttemptPatch {
		// Is the patch for us?
		if *latestPlatformRelease.PatchFor == currentUIND {
			fmt.Printf("Attempting to download and apply patch from: %s\n", *latestPlatformRelease.PatchURL)
			downloadURL = *latestPlatformRelease.PatchURL
			opts.Patcher = update.NewBSDiffPatcher()

			// Set checksum and signature for the patch file
			expectedChecksum, err = hex.DecodeString(*latestPlatformRelease.PatchChecksum)
			if err != nil {
				return fmt.Errorf("failed to decode patch checksum: %w", err)
			}
			expectedSignature, err = base64.StdEncoding.DecodeString(*latestPlatformRelease.PatchSignature)
			if err != nil {
				return fmt.Errorf("failed to decode patch signature: %w", err)
			}
		} else {
			// Warn the user that the patch is not the current UIND and fallback to a full update
			fmt.Printf("Warning: Patch is for UIND %d, but current UIND is %d. Falling back to full update.\n", *latestPlatformRelease.PatchFor, currentUIND)
			shouldAttemptPatch = false
		}

	}

	if !shouldAttemptPatch {
		if latestPlatformRelease.IsPatch {
			if latestPlatformRelease.PatchURL == nil || *latestPlatformRelease.PatchURL == "" {
				fmt.Println("Warning: Release is marked as patch but no patch_url for current platform. Falling back to full update.")
			} else if latestPlatformRelease.PatchFor == nil || *latestPlatformRelease.PatchFor != currentUIND {
				fmt.Printf("Warning: Patch is for UIND %d, but current UIND is %d. Falling back to full update.\n", *latestPlatformRelease.PatchFor, currentUIND)
			} else { // Missing patch checksum or signature
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
		expectedSignature, err = base64.StdEncoding.DecodeString(latestPlatformRelease.Signature)
		if err != nil {
			return fmt.Errorf("failed to decode full binary signature: %w", err)
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

	// Create a buffer to store the update content for checksum verification
	updateContent := new(bytes.Buffer)
	teeReader := io.TeeReader(resp.Body, updateContent)

	err = update.Apply(teeReader, opts)
	if err != nil {
		return fmt.Errorf("failed to apply update: %w", err)
	}

	fmt.Println("Update applied successfully!")
	return nil
}
