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
	"runtime"
	"strconv"
	"strings"

	"github.com/inconshreveable/go-update"

	_ "embed"
)

// App metadata injected at compile time (these will be passed to NetUpdater)
var (
	AppVersion    = "0.0.0"
	AppUIND       = "0"
	AppChannel    = "default"
	AppBuildTime  = "unknown"
	AppCommitHash = "unknown"
)

//go:embed public.pem
var appPublicKey []byte

// NetUpSourceInfo holds URLs for a specific OS/Architecture within a release.
type NetUpSourceInfo struct {
	IsPatch        bool    `json:"is_patch"`
	URL            string  `json:"url"`
	PatchURL       *string `json:"patch_url"`       // Pointer to string to allow null
	PatchFor       *int    `json:"patch_for"`       // Pointer to int to allow null
	Checksum       string  `json:"checksum"`        // Checksum of the full binary
	Signature      string  `json:"signature"`       // Signature of the full binary
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
	AppVersion      string
	AppUIND         int
	AppChannel      string
	AppBuildTime    string
	AppCommitHash   string
	PublicKeyPEM    []byte
	DeploymentURL   string // Renamed from DeployURL to avoid conflict and be more descriptive
	CurrentPlatform string
}

// NewNetUpdater creates and initializes a new NetUpdater instance.
func NewNetUpdater(version, uindStr, channel, buildTime, commitHash, deployURL string, publicKey []byte) (*NetUpdater, error) {
	currentUIND, err := strconv.Atoi(uindStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AppUIND: %w", err)
	}

	return &NetUpdater{
		AppVersion:      version,
		AppUIND:         currentUIND,
		AppChannel:      channel,
		AppBuildTime:    buildTime,
		AppCommitHash:   commitHash,
		PublicKeyPEM:    publicKey,
		DeploymentURL:   deployURL,
		CurrentPlatform: fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH),
	}, nil
}

// GetLatestVersion fetches the deploy file and determines the latest compatible release
// for the updater's current channel and platform.
func (nu *NetUpdater) GetLatestVersion() (*NetUpReleaseInfo, error) {
	resp, err := http.Get(nu.DeploymentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deploy.json from %s: %w", nu.DeploymentURL, err)
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

	releases, ok := deployFile.Channels[nu.AppChannel]
	if !ok || len(releases) == 0 {
		return nil, fmt.Errorf("no releases found for channel '%s'", nu.AppChannel)
	}

	var latest *NetUpReleaseInfo
	for i := range releases {
		release := &releases[i]
		// Ensure the release has source info for the current platform
		if _, ok := release.Sources[nu.CurrentPlatform]; ok {
			if latest == nil || release.UIND > latest.UIND {
				latest = release
			}
		} else {
			fmt.Printf("Skipping release %s (UIND %d) - no build found for %s\n", release.Semver, release.UIND, nu.CurrentPlatform)
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no compatible releases found for channel '%s' on %s", nu.AppChannel, nu.CurrentPlatform)
	}
	return latest, nil
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
	latestPlatformRelease, ok := latestRelease.Sources[nu.CurrentPlatform]
	if !ok {
		return fmt.Errorf("no update source found for current platform: %s", nu.CurrentPlatform)
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
		if *latestPlatformRelease.PatchFor == nu.AppUIND {
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
			isPatchAttempt = true
		} else {
			// Warn the user that the patch is not for the current UIND and fallback to a full update
			fmt.Printf("Warning: Patch is for UIND %d, but current UIND is %d. Falling back to full update.\n", *latestPlatformRelease.PatchFor, nu.AppUIND)
			shouldAttemptPatch = false // Force fallback
		}
	}

	if !isPatchAttempt { // If we didn't attempt a patch, or if the patch attempt failed/was skipped
		if latestPlatformRelease.IsPatch {
			if latestPlatformRelease.PatchURL == nil || *latestPlatformRelease.PatchURL == "" {
				fmt.Println("Warning: Release is marked as patch but no patch_url for current platform. Falling back to full update.")
			} else if latestPlatformRelease.PatchFor == nil || *latestPlatformRelease.PatchFor != nu.AppUIND {
				// This case is already covered above, but kept for clarity if logic changes.
				// It implies shouldAttemptPatch was false because PatchFor didn't match.
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

	err = update.Apply(resp.Body, opts)
	if err != nil {
		return fmt.Errorf("failed to apply update: %w", err)
	}

	fmt.Println("Update applied successfully!")
	return nil
}

func main() {
	// Initialize the NetUpdater with app details and the deployment URL
	updater, err := NewNetUpdater(AppVersion, AppUIND, AppChannel, AppBuildTime, AppCommitHash, "https://raw.githubusercontent.com/sbamboo/go-update-test/refs/heads/main/t3/deploy.json", appPublicKey)
	if err != nil {
		fmt.Printf("Failed to initialize updater: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("--- Go Update CLI App ---")
	fmt.Printf("Version: %s (UIND: %d)\n", updater.AppVersion, updater.AppUIND)
	fmt.Printf("Channel: %s\n", updater.AppChannel)
	fmt.Printf("Build Time: %s\n", updater.AppBuildTime)
	fmt.Printf("Commit Hash: %s\n", updater.AppCommitHash)
	fmt.Printf("Running on: %s\n", updater.CurrentPlatform)

	latestRelease, err := updater.GetLatestVersion()
	if err != nil {
		fmt.Printf("Error checking for updates: %v\n", err)
	} else if latestRelease != nil && latestRelease.UIND > updater.AppUIND {
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
			if latestRelease == nil || latestRelease.UIND <= updater.AppUIND {
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
				break // Exit after successful update to encourage restart
			}
		} else {
			// Update the updater's channel property for the current session
			updater.AppChannel = input
			fmt.Printf("Switching to channel: %s\n", updater.AppChannel)
			latestRelease, err = updater.GetLatestVersion()
			if err != nil {
				fmt.Printf("Error checking for updates in channel '%s': %v\n", updater.AppChannel, err)
			} else if latestRelease != nil && latestRelease.UIND > updater.AppUIND {
				fmt.Printf("\n--- Update Available for Channel %s! ---\n", updater.AppChannel)
				fmt.Printf("New Version: %s (UIND: %d)\n", latestRelease.Semver, latestRelease.UIND)
				fmt.Printf("Notes: %s\n", latestRelease.Notes)
				fmt.Println("-----------------------------------------\n")
			} else {
				fmt.Printf("No newer version available in channel '%s'.\n", updater.AppChannel)
			}
		}
	}
}
