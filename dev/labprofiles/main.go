// Command labprofiles adds a PADL profile for each directory in the local lab,
// so the whole thing can be browsed by hand without typing six connection
// forms.
//
//	make lab-profiles              # start everything, add the profiles
//	go run ./dev/labprofiles -rm   # take the profiles away again
//
// It writes to the real profiles.yaml and, unless -prompt is given, puts each
// lab password in the OS keychain — the same two places PADL itself writes when
// you save a server in the UI. Only profiles whose ID starts with "lab-" are
// touched; anything else in the file is left exactly as it was.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mnorrsken/padl/internal/config"
)

// idPrefix namespaces everything this command owns. -rm removes exactly the
// profiles carrying it and nothing else.
const idPrefix = "lab-"

// labProfile is one entry to write, with the password that goes with it.
type labProfile struct {
	profile  config.Profile
	password string
	// note is what to print beside it: why this profile is worth having.
	note string
}

func main() {
	var (
		configDir = flag.String("config", "", "write to this config directory instead of the real one")
		remove    = flag.Bool("rm", false, "remove the lab profiles and their keychain entries")
		prompt    = flag.Bool("prompt", false, "ask for the password on connect instead of using the keychain")
	)
	flag.Parse()

	if err := run(*configDir, *remove, *prompt); err != nil {
		fmt.Fprintln(os.Stderr, "labprofiles:", err)
		os.Exit(1)
	}
}

func run(configDir string, remove, prompt bool) error {
	path := config.ProfilesPath()
	if configDir != "" {
		path = strings.TrimRight(configDir, "/") + "/profiles.yaml"
	}

	store, err := config.LoadStore(path)
	if err != nil {
		return err
	}
	secrets := config.NewSecrets()

	if remove {
		return removeAll(store, secrets, path)
	}

	profiles := labProfiles(prompt)
	if len(profiles) == 0 {
		return fmt.Errorf("nothing to add")
	}

	for _, lp := range profiles {
		if err := store.Put(lp.profile); err != nil {
			return fmt.Errorf("add %s: %w", lp.profile.ID, err)
		}
	}

	fmt.Printf("profiles: %s\n", path)
	for _, lp := range profiles {
		fmt.Printf("  %-18s %-38s %s\n", lp.profile.ID, lp.profile.URL(), lp.note)
	}

	// The password goes where PADL would have put it if you had ticked "save"
	// in the UI. Say so out loud: writing to somebody's keychain is not
	// something to do quietly.
	if prompt {
		fmt.Println("\npasswords: not saved, PADL will ask on connect")
		for _, lp := range profiles {
			fmt.Printf("  %-18s %s\n", lp.profile.ID, lp.password)
		}
	} else {
		fmt.Printf("\npasswords: saved to the OS keychain under service %q\n", config.KeyringService)
		var failed []string
		for _, lp := range profiles {
			if err := secrets.Store(lp.profile, lp.password); err != nil {
				failed = append(failed, fmt.Sprintf("  %-18s %v", lp.profile.ID, err))
			}
		}
		for _, f := range failed {
			fmt.Println(f)
		}
		if len(failed) > 0 {
			fmt.Println("  (run again with -prompt to be asked instead)")
		}
	}

	fmt.Println("\nrun padl, press p, and pick one. The certificates are self-signed,")
	fmt.Println("so the first connect to each asks you to trust it — that is the point.")
	fmt.Println("\ngo run ./dev/labprofiles -rm  takes all of this away again.")
	return nil
}

func removeAll(store *config.Store, secrets *config.Secrets, path string) error {
	var removed []string
	for _, p := range store.List() {
		if !strings.HasPrefix(p.ID, idPrefix) {
			continue
		}
		// Forget first: once the profile is gone there is nothing left to say
		// which keychain entry belonged to it.
		if err := secrets.Forget(p); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: keychain: %v\n", p.ID, err)
		}
		if err := store.Delete(p.ID); err != nil {
			return fmt.Errorf("remove %s: %w", p.ID, err)
		}
		removed = append(removed, p.ID)
	}
	sort.Strings(removed)
	if len(removed) == 0 {
		fmt.Printf("nothing to remove in %s\n", path)
		return nil
	}
	fmt.Printf("removed from %s:\n", path)
	for _, id := range removed {
		fmt.Printf("  %s\n", id)
	}
	return nil
}

// labProfiles is the set to write. The ports match dev/docker-compose.yml and
// dev/lab-edir.sh.
func labProfiles(prompt bool) []labProfile {
	ref := config.PasswordKeyring
	if prompt {
		ref = config.PasswordPrompt
	}

	simple := func(id, name, host string, port int, sec config.Security, bindDN, baseDN, password, note string) labProfile {
		return labProfile{
			profile: config.Profile{
				ID:          idPrefix + id,
				Name:        name,
				Host:        host,
				Port:        port,
				Security:    sec,
				Bind:        config.BindSimple,
				BindDN:      bindDN,
				BaseDN:      baseDN,
				PasswordRef: ref,
			},
			password: password,
			note:     note,
		}
	}

	profiles := []labProfile{
		simple("openldap", "OpenLDAP (lab)", "127.0.0.1", 13636, config.SecurityLDAPS,
			"cn=admin,dc=example,dc=com", "", "padl-lab",
			"the standards-compliant one"),
		simple("lldap", "lldap (lab)", "127.0.0.1", 13390, config.SecurityNone,
			"uid=admin,ou=people,dc=example,dc=com", "", "padl-lab",
			"flat one-level results, no paging"),
		simple("ad", "Active Directory (lab)", "127.0.0.1", 13638, config.SecurityLDAPS,
			"CN=Administrator,CN=Users,DC=ad,DC=example,DC=com", "DC=ad,DC=example,DC=com", "Padl-Lab-1",
			"GUIDs, SIDs, flag words, paging"),
		simple("ad-starttls", "Active Directory over StartTLS (lab)", "127.0.0.1", 13392, config.SecurityStartTLS,
			"administrator@ad.example.com", "DC=ad,DC=example,DC=com", "Padl-Lab-1",
			"the same domain, bound by UPN"),
	}

	if edir, ok := edirProfile(ref); ok {
		profiles = append(profiles, edir)
	}
	return profiles
}

// edirProfile is built only when dev/edir.env has been filled in. Its defaults
// match dev/lab-edir.sh, and the base DN is not optional: eDirectory publishes
// an empty namingContexts, so PADL has nothing to discover.
func edirProfile(ref config.PasswordRef) (labProfile, bool) {
	password := os.Getenv("PADL_EDIR_PASSWORD")
	if password == "" {
		return labProfile{}, false
	}

	base := envOr("PADL_EDIR_BASE_DN", "o=padl")
	// The same variable the manual tests read, so one file drives both.
	bindDN := envOr("PADL_EDIR_BIND_DN", "cn=admin,"+base)
	port, err := strconv.Atoi(envOr("PADL_EDIR_LDAPS_PORT", "13637"))
	if err != nil {
		return labProfile{}, false
	}

	return labProfile{
		profile: config.Profile{
			ID:       idPrefix + "edir",
			Name:     "eDirectory (lab)",
			Host:     envOr("PADL_EDIR_HOST", "127.0.0.1"),
			Port:     port,
			Security: config.SecurityLDAPS,
			Bind:     config.BindSimple,
			// LDAP form, with a comma. ndsconfig wanted the dotted one.
			BindDN:      bindDN,
			BaseDN:      base,
			PasswordRef: ref,
		},
		password: password,
		note:     "empty namingContexts, so the base DN is set",
	}, true
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
