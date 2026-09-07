package cli

import (
	"runtime/debug"
	"strings"
	"testing"
)

// A user who follows the documented install command must be able to say what
// they are running.
//
// `go install <module>/cmd/appsec@v0.1.0` never runs the Makefile, so the
// -ldflags value stays at its development default and every installed copy
// reported "0.0.0-dev". That makes every bug report ambiguous about what was
// running, which for a security tool is worse than cosmetic.
func TestVersionPrecedence(t *testing.T) {
	tagged := &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}
	devel := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0c1c1a4068a6e677f4cf1b4f068e741c810412fd"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	dirty := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0c1c1a4068a6e677f4cf1b4f068e741c810412fd"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	for name, tc := range map[string]struct {
		linked string
		info   *debug.BuildInfo
		want   string
	}{
		"a release build's linked version wins": {"v0.1.0", devel, "v0.1.0"},
		"go install records the module version": {devVersion, tagged, "v0.1.0"},
		"a checkout falls back to the revision": {devVersion, devel, "0.0.0-dev+0c1c1a4068a6"},
		"a dirty checkout says so":              {devVersion, dirty, "0.0.0-dev+0c1c1a4068a6.dirty"},
		"nothing known is honest about it":      {devVersion, nil, devVersion},
		"an empty linked value is not reported": {"", tagged, "v0.1.0"},
	} {
		if got := versionFrom(tc.linked, tc.info); got != tc.want {
			t.Errorf("%s: versionFrom(%q, …) = %q, want %q", name, tc.linked, got, tc.want)
		}
	}
}

// The version command exists and identifies the build well enough for a bug
// report, without the reporter having to be told what to paste.
func TestVersionCommandIdentifiesTheBuild(t *testing.T) {
	_, out, _ := run(t, "version")
	for _, want := range []string{"appsec ", "go:", "platform:", "schema:"} {
		if !strings.Contains(out, want) {
			t.Errorf("`appsec version` omits %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "%!") {
		t.Errorf("the version output has a formatting error:\n%s", out)
	}
}
