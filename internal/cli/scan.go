package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/application-security-framework/internal/check"
	"github.com/jaylordibe/application-security-framework/internal/config"
	"github.com/jaylordibe/application-security-framework/internal/engine"
	"github.com/jaylordibe/application-security-framework/internal/httpx"
	"github.com/jaylordibe/application-security-framework/internal/model"
	"github.com/jaylordibe/application-security-framework/internal/openapi"
	"github.com/jaylordibe/application-security-framework/internal/outcome"
	"github.com/jaylordibe/application-security-framework/internal/redact"
	"github.com/jaylordibe/application-security-framework/internal/scope"
	"github.com/jaylordibe/application-security-framework/internal/store"
)

func newScanCommand(stdout, stderr io.Writer) *cobra.Command {
	var (
		configPath string
		specFile   string
		specURL    string
		profile    string
		outputDir  string
		noProbe    bool
	)

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Assess a target application",
		Long: "Assess an application you own or are explicitly authorized to test.\n\n" +
			"The target URL you supply is the authorization you are giving: Assay will\n" +
			"contact that origin and nothing else unless you widen the scope in\n" +
			"assay.yaml.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(configPath, args)
			if err != nil {
				return err
			}
			if specFile != "" {
				cfg.Discovery.OpenAPIFile = specFile
				cfg.Discovery.OpenAPIURL = ""
			}
			if specURL != "" {
				cfg.Discovery.OpenAPIURL = specURL
				cfg.Discovery.OpenAPIFile = ""
			}
			if profile != "" {
				cfg.Assessment.Profile = profile
			}
			if outputDir != "" {
				cfg.Output.Dir = outputDir
			}
			if noProbe {
				no := false
				cfg.Discovery.ProbeWellKnownPaths = &no
			}
			if err := cfg.Validate(); err != nil {
				return fail(ExitUsage, "%v", err)
			}
			return runScan(cmd.Context(), cfg, stdout, stderr)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to assay.yaml (default: ./assay.yaml if present)")
	cmd.Flags().StringVar(&specFile, "spec", "", "path to an OpenAPI document on disk")
	cmd.Flags().StringVar(&specURL, "spec-url", "", "URL of an OpenAPI document served by the target")
	cmd.Flags().StringVar(&profile, "profile", "", "safety profile: discovery, verification, intrusive")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "run output directory (default: .assay)")
	cmd.Flags().BoolVar(&noProbe, "no-probe", false, "do not probe well-known specification paths")
	return cmd
}

// resolveConfig loads assay.yaml if present, then applies the positional target.
//
// The URL the operator typed is treated as the authorization they granted: the
// target's own origin is always in scope, and loopback targets enable private
// addressing automatically. Requiring a config file before a first scan would
// make the documented first command fail.
func resolveConfig(configPath string, args []string) (config.Config, error) {
	cfg := config.Default()

	path := configPath
	if path == "" {
		if _, err := os.Stat("assay.yaml"); err == nil {
			path = "assay.yaml"
		}
	}
	if path != "" {
		loaded, err := config.Load(path)
		if err != nil {
			return config.Config{}, fail(ExitUsage, "%v", err)
		}
		cfg = loaded
	}

	if len(args) == 1 {
		cfg.Target.BaseURL = args[0]
	}
	if cfg.Target.BaseURL == "" {
		return config.Config{}, fail(ExitUsage,
			"no target given.\n\n  Try:  assay scan http://localhost:3000\n"+
				"  Or:   assay init    (to create an assay.yaml)")
	}
	if !strings.Contains(cfg.Target.BaseURL, "://") {
		cfg.Target.BaseURL = "http://" + cfg.Target.BaseURL
	}
	// The URL the operator typed is the authorization they granted, so a loopback
	// target enables private addressing. A configuration file that already said
	// so is unaffected; one that said nothing gets the convenience.
	if isLoopbackTarget(cfg.Target.BaseURL) {
		cfg.Scope.AllowPrivateAddresses = true
	}
	return cfg, nil
}

// isLoopbackTarget reports whether the operator typed a loopback address.
//
// It parses the host as an address rather than matching a string prefix. A
// prefix test would treat an attacker-registrable name such as
// "127.0.0.1.nip.io" as loopback and silently enable private addressing for the
// entire run — overriding whatever the configuration said, and opening exactly
// the internal-service access the scope policy exists to prevent.
func isLoopbackTarget(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A name, not an address. Names are never assumed to be loopback: the
		// name is not the address it resolves to.
		return false
	}
	return addr.IsLoopback()
}

func runScan(ctx context.Context, cfg config.Config, stdout, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now
	runID := newRunID(now())

	policy, err := cfg.ScopePolicy()
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	red := redact.New()

	client, err := httpx.New(httpx.Options{
		Policy:            policy,
		Redactor:          red,
		Timeout:           time.Duration(cfg.Assessment.TimeoutSeconds) * time.Second,
		MaxBodyBytes:      httpx.DefaultMaxBodyBytes,
		Now:               now,
		RequestsPerSecond: cfg.Assessment.RequestsPerSecond,
	})
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	defer client.Close()

	if cfg.Scope.AllowPrivateAddresses {
		fmt.Fprintf(stderr, "assay: scope: %s (private addresses permitted for this target)\n", cfg.Target.BaseURL)
	}
	if !store.PermissionsEnforced() {
		fmt.Fprintln(stderr,
			"assay: warning: this platform does not enforce owner-only file permissions, "+
				"so the run directory may be readable by other users")
	}

	surface, err := discover(ctx, cfg, client, now)
	if err != nil {
		return fail(ExitAborted, "discovery failed: %v", err)
	}

	// The run directory is created before the assessment starts, so evidence can
	// be written as it is captured rather than buffered in memory until the end.
	run, err := store.Create(cfg.Output.Dir, runID, now())
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	if err := run.WriteFingerprintKey(red.FingerprintKey()); err != nil {
		return fail(ExitInternal, "%v", err)
	}

	checks := []engine.Check{
		check.AuthRequired{
			Client: client,
			Signals: outcome.Signals{
				ErrorCodePointer: cfg.Outcome.ErrorCodePointer,
				DeniedCodes:      cfg.Outcome.DeniedCodes,
				NotFoundCodes:    cfg.Outcome.NotFoundCodes,
			},
			BaselineProbes: 2,
		},
	}

	res, err := engine.Run(ctx, engine.Options{
		RunID:                runID,
		Target:               cfg.Target.BaseURL,
		TargetName:           cfg.Target.Name,
		Profile:              cfg.Profile(),
		Surface:              surface,
		Checks:               checks,
		Environment:          engine.Environment{Name: cfg.Environment.Name, Differences: cfg.Environment.Differences},
		ScopeEntries:         scopeStrings(policy),
		AllowPrivate:         cfg.Scope.AllowPrivateAddresses,
		ExcludeOperations:    cfg.Assessment.ExcludeOperations,
		ExcludeAuthEndpoints: cfg.ShouldExcludeAuthEndpoints(),
		Concurrency:          cfg.Assessment.Concurrency,
		RequestsPerSecond:    cfg.Assessment.RequestsPerSecond,
		Now:                  now,
		EvidenceSink:         run.PutEvidence,
	})
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	res.OutOfScopeHosts = policy.OutOfScopeHosts()

	return persistAndSummarize(res, run, cfg.Policy, stdout, stderr)
}

// discover builds the attack surface.
func discover(ctx context.Context, cfg config.Config, client *httpx.Client, now func() time.Time) (engine.Surface, error) {
	var raw []byte
	var source model.Source

	switch {
	case cfg.Discovery.OpenAPIFile != "":
		path := filepath.Clean(cfg.Discovery.OpenAPIFile)
		data, err := os.ReadFile(path)
		if err != nil {
			return engine.Surface{}, fmt.Errorf("cannot read specification: %w", err)
		}
		if len(data) > openapi.MaxDocumentBytes {
			return engine.Surface{}, fmt.Errorf("specification exceeds %d bytes", openapi.MaxDocumentBytes)
		}
		raw = data
		source = openapi.SourceAt(model.SourceOpenAPIFile, path, now())

	case cfg.Discovery.OpenAPIURL != "":
		data, err := fetchSpec(ctx, client, cfg.Discovery.OpenAPIURL)
		if err != nil {
			return engine.Surface{}, err
		}
		raw = data
		source = openapi.SourceAt(model.SourceOpenAPIURL, cfg.Discovery.OpenAPIURL, now())

	case cfg.ShouldProbeWellKnownPaths():
		base := strings.TrimRight(cfg.Target.BaseURL, "/")
		// Track whether the probes were refused by scope rather than simply
		// finding nothing. Reporting "no document found" when in fact every
		// request was refused would misdescribe what happened, which is the
		// failure this project exists to prevent.
		var scopeRefusal error
		var parseFailure error
		for _, p := range openapi.WellKnownPaths() {
			candidate := base + p
			data, err := fetchSpec(ctx, client, candidate)
			if err != nil {
				var oos *httpx.ErrOutOfScope
				if errors.As(err, &oos) && scopeRefusal == nil {
					scopeRefusal = oos
				}
				continue
			}
			if len(data) == 0 {
				continue
			}
			if _, perr := openapi.Parse(data, cfg.Target.BaseURL, model.Source{}); perr != nil {
				// A target serving only a malformed document should be told it
				// was malformed, not that nothing was found.
				if parseFailure == nil {
					parseFailure = fmt.Errorf("%s: %v", p, perr)
				}
				continue
			}
			raw = data
			source = openapi.SourceAt(model.SourceOpenAPIURL, candidate, now())
			break
		}
		if raw == nil && scopeRefusal != nil {
			return engine.Surface{}, fmt.Errorf(
				"every request to the target was refused by the scope policy, so nothing "+
					"was assessed\n\n  %v\n\n"+
					"  This is a refusal, not a clean result. Cloud metadata addresses are\n"+
					"  always denied. To assess a different host, widen scope deliberately:\n"+
					"    scope.include in assay.yaml", scopeRefusal)
		}
		if raw == nil && parseFailure != nil {
			return engine.Surface{}, fmt.Errorf(
				"a document was served at a well-known path but could not be parsed\n\n"+
					"  %v\n\n"+
					"  This is a parse failure, not an absence. Point Assay at a valid\n"+
					"  document:\n"+
					"    assay scan <target> --spec ./openapi.json", parseFailure)
		}
		if raw == nil {
			return engine.Surface{}, fmt.Errorf(
				"no OpenAPI document found.\n\n" +
					"  Assay derives what should be protected from the application's own\n" +
					"  specification. Without one it has no oracle and would be guessing.\n\n" +
					"  Point it at a document:\n" +
					"    assay scan <target> --spec ./openapi.json\n" +
					"    assay scan <target> --spec-url <target>/api/docs-json")
		}
	default:
		return engine.Surface{}, fmt.Errorf("no specification configured and probing is disabled")
	}

	res, err := openapi.Parse(raw, cfg.Target.BaseURL, source)
	if err != nil {
		return engine.Surface{}, err
	}
	return engine.Surface{
		SpecDerived:  true,
		SpecSource:   source,
		SpecTitle:    res.Title,
		SpecVersion:  res.Version,
		Fidelity:     res.Fidelity,
		Operations:   res.Operations,
		ExternalRefs: res.ExternalRefs,
		Warnings:     res.Warnings,
	}, nil
}

func fetchSpec(ctx context.Context, client *httpx.Client, rawURL string) ([]byte, error) {
	ex, err := client.Do(ctx, httpx.Request{
		Method: "GET",
		URL:    rawURL,
		Header: map[string][]string{"Accept": {"application/json, application/yaml, */*"}},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot fetch specification: %w", err)
	}
	if ex.Response == nil || ex.Response.Status < 200 || ex.Response.Status > 299 {
		status := 0
		if ex.Response != nil {
			status = ex.Response.Status
		}
		return nil, fmt.Errorf("specification request returned status %d", status)
	}
	return ex.Response.Body, nil
}

func scopeStrings(p *scope.Policy) []string { return p.EntryStrings() }

// newRunID is time-ordered so runs sort naturally, with a random suffix so two
// runs started in the same second cannot collide.
func newRunID(t time.Time) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return t.UTC().Format("20060102T150405Z")
	}
	return t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
