package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/inconshreveable/go-update"
)

var (
	Version = "0.0.1d" // injected via -ldflags
	Commit  = "dev"
	Uind    = "1"
	Channel = "dev" // default channel, can be "release" or "dev"
)

type ReleaseInfo struct {
	Uind         int       `json:"uind"`
	Semver       string    `json:"semver"`
	Date         time.Time `json:"date"`
	Notes        string    `json:"notes"`
	Checksum     string    `json:"checksum"`
	ChecksumType string    `json:"checksum_type"`
	Context      string    `json:"context"`
	URL          string    `json:"url"`
	Size         int       `json:"size"`
}

type UpdateData struct {
	Release []ReleaseInfo `json:"release"`
	Dev     []ReleaseInfo `json:"dev"`
}

func getUind() int {
	u, err := strconv.Atoi(Uind)
	if err != nil {
		return 0
	}
	return u
}

const deployURL = "https://raw.githubusercontent.com/sbamboo/go-update-test/refs/heads/main/deploy.json"

func fetchUpdateData() (*UpdateData, error) {
	resp, err := http.Get(deployURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data UpdateData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func getLatest(data *UpdateData, current_channel string) *ReleaseInfo {
	var list []ReleaseInfo
	if current_channel == "dev" {
		list = data.Dev
	} else {
		list = data.Release
	}

	var latest *ReleaseInfo
	for i := range list {
		if latest == nil || list[i].Uind > latest.Uind {
			latest = &list[i]
		}
	}
	return latest
}

func isNewer(currentUind int, latest *ReleaseInfo) bool {
	return latest != nil && latest.Uind > currentUind
}

func performUpdate(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return fmt.Errorf("copy error: %w", err)
	}

	err = update.Apply(buf, update.Options{})
	if err != nil {
		return fmt.Errorf("update apply error: %w", err)
	}

	return nil
}

func main() {
	a := app.New()
	w := a.NewWindow("Hello World Updater")
	current_channel := Channel

	versionLabel := widget.NewLabel(fmt.Sprintf("Semver: %s\nCommit: %s\nUind: %s", Version, Commit, Uind))
	helloLabel := widget.NewLabel("Hello world")
	updateBox := container.NewVBox()
	var toggleButtonText string
	if current_channel == "dev" {
		toggleButtonText = "Switch to Release channel"
	} else {
		toggleButtonText = "Switch to Dev channel"
	}
	toggleButton := widget.NewButton(toggleButtonText, func() {})

	var latest *ReleaseInfo

	updateUI := func() {
		versionLabel.SetText(fmt.Sprintf("Semver: %s\nCommit: %s\nUind: %s\nChannel: %s", Version, Commit, Uind, Channel))
	}

	checkForUpdate := func(forceUpdate bool) {
		data, err := fetchUpdateData()
		if err != nil {
			fyne.Do(func() {
				updateBox.Objects = []fyne.CanvasObject{widget.NewLabel("Error checking updates.")}
				updateBox.Refresh()
			})
			return
		}
		latest = getLatest(data, current_channel)

		// If forceUpdate is true, always show update prompt.
		// Otherwise, show only if newer.
		if forceUpdate || isNewer(getUind(), latest) {
			fyne.Do(func() {
				updateBox.Objects = []fyne.CanvasObject{
					widget.NewLabel(fmt.Sprintf("🔔 New update available: %s", latest.Semver)),
					widget.NewButton("Update Now", func() {
						go func() {
							err := performUpdate(latest.URL)
							fyne.Do(func() {
								if err != nil {
									updateBox.Objects = []fyne.CanvasObject{widget.NewLabel("❌ Update failed: " + err.Error())}
								} else {
									updateBox.Objects = []fyne.CanvasObject{widget.NewLabel("✅ Update successful. Please restart the app.")}
								}
								updateBox.Refresh()
							})
						}()
					}),
				}
				updateBox.Refresh()
			})
		} else {
			fyne.Do(func() {
				updateBox.Objects = []fyne.CanvasObject{widget.NewLabel("✅ You are up to date.")}
				updateBox.Refresh()
			})
		}
	}

	toggleButton.OnTapped = func() {
		if current_channel == "release" {
			current_channel = "dev"
			toggleButton.SetText("Switch to Release channel")
		} else {
			current_channel = "release"
			toggleButton.SetText("Switch to Dev channel")
		}
		updateUI()
		force := false
		if current_channel != Channel {
			force = true
		}
		go checkForUpdate(force)
	}

	w.SetContent(container.NewVBox(
		helloLabel,
		versionLabel,
		toggleButton,
		updateBox,
	))

	updateUI()
	go checkForUpdate(false)

	w.Resize(fyne.NewSize(400, 300))
	w.ShowAndRun()
}
