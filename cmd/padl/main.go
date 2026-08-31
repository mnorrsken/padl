// Command padl is a terminal LDAP browser.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gdamore/tcell/v2"

	"github.com/mnorrsken/padl/internal/config"
	"github.com/mnorrsken/padl/internal/ui"
	"github.com/mnorrsken/padl/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "padl:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		profileID   = flag.String("profile", "", "connect to this profile ID at startup")
		configDir   = flag.String("config", "", "override the config directory")
		showVersion = flag.Bool("version", false, "print the version and exit")
		showPaths   = flag.Bool("paths", false, "print the config file locations and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("padl", version.String())
		return nil
	}

	profilesPath, trustPath := config.ProfilesPath(), config.TrustPath()
	if *configDir != "" {
		profilesPath = *configDir + "/profiles.yaml"
		trustPath = *configDir + "/trust.yaml"
	}

	if *showPaths {
		fmt.Println("profiles:", profilesPath)
		fmt.Println("trust:   ", trustPath)
		fmt.Println("secrets: ", "OS keychain, service "+config.KeyringService)
		return nil
	}

	profiles, err := config.LoadStore(profilesPath)
	if err != nil {
		return err
	}
	trust, err := config.LoadTrustStore(trustPath)
	if err != nil {
		return err
	}

	// The screen is created here rather than left to tview so the app can also
	// use it for the terminal's OSC 52 clipboard.
	screen, err := tcell.NewScreen()
	if err != nil {
		return fmt.Errorf("open terminal: %w", err)
	}

	app := ui.New(ui.Options{
		Profiles:       profiles,
		Trust:          trust,
		Secrets:        config.NewSecrets(),
		Screen:         screen,
		InitialProfile: *profileID,
	})
	return app.Run()
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `padl %s — a terminal LDAP browser

Usage:
  padl [flags]

Flags:
`, version.String())
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), `
Servers are configured inside the app: press p, then a.
Bind passwords are never written to the profile file — they go to the OS
keychain, come from PADL_PASSWORD_<ID>, or are typed on each connect.
`)
}
