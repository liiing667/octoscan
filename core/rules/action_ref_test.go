package rules

import "testing"

func TestParseActionRef(t *testing.T) {
	const sha = "11bd71901bbe5b1630ceea73d27597364c9af683"

	tests := []struct {
		spec  string
		kind  SourceKind
		owner string
		repo  string
		path  string
		ref   string
		pin   PinKind
	}{
		{"actions/checkout@v4", SourceRemote, "actions", "checkout", "", "v4", PinMutable},
		{"Actions/Checkout@v4", SourceRemote, "Actions", "Checkout", "", "v4", PinMutable},
		{"actions/checkout@" + sha, SourceRemote, "actions", "checkout", "", sha, PinSHA},
		{"actions/checkout@11bd719", SourceRemote, "actions", "checkout", "", "11bd719", PinShortSHA},
		{"actions/checkout@main", SourceRemote, "actions", "checkout", "", "main", PinMutable},
		{"github/codeql-action/analyze@v3", SourceRemote, "github", "codeql-action", "analyze", "v3", PinMutable},
		{"github/codeql-action/actions/upload@v3", SourceRemote, "github", "codeql-action", "actions/upload", "v3", PinMutable},
		{"owner/repo", SourceRemote, "owner", "repo", "", "", PinNone},
		{"owner/repo@", SourceRemote, "owner", "repo", "", "", PinNone},
		{"./.github/actions/build", SourceLocal, "", "", "./.github/actions/build", "", PinNone},
		{"$/.github/actions/lint", SourceLocal, "", "", "$/.github/actions/lint", "", PinNone},
		{"docker://alpine:3.19", SourceDocker, "", "", "alpine", "3.19", PinMutable},
		{"docker://alpine@sha256:aBcDef0123456789aBcDef0123456789aBcDef0123456789aBcDef0123456789", SourceDocker, "", "", "alpine", "sha256:aBcDef0123456789aBcDef0123456789aBcDef0123456789aBcDef0123456789", PinDigest},
		{"docker://localhost:5000/image:tag", SourceDocker, "", "", "localhost:5000/image", "tag", PinMutable},
		{"docker://alpine", SourceDocker, "", "", "alpine", "", PinNone},
		{"checkout@v4", SourceInvalid, "", "", "", "", PinNone},
		{"/checkout@v4", SourceInvalid, "", "", "", "", PinNone},
		{"actions/@v4", SourceInvalid, "", "", "", "", PinNone},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got := ParseActionRef(tt.spec)
			if got.Kind != tt.kind || got.Owner != tt.owner || got.Repo != tt.repo || got.Path != tt.path || got.Ref != tt.ref || got.Pin != tt.pin {
				t.Fatalf("got %+v", got)
			}

			if got.Raw != tt.spec {
				t.Fatalf("Raw = %q, want %q", got.Raw, tt.spec)
			}
		})
	}
}

func TestActionRefIs(t *testing.T) {
	tests := []struct {
		spec   string
		action string
		want   bool
	}{
		// the identity does not depend on the case, the ref or how it is pinned
		{"actions/checkout@v4", "actions/checkout", true},
		{"Actions/Checkout@v4", "actions/checkout", true},
		{"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "actions/checkout", true},
		{"actions/checkout@11bd719", "actions/checkout", true},
		// a lookalike repository is another source
		{"actions/checkout-evil@v4", "actions/checkout", false},
		{"actions/checkout2@v4", "actions/checkout", false},
		{"evil/checkout@v4", "actions/checkout", false},
		// a monorepo path keeps the source of the repository
		{"github/codeql-action/analyze@v3", "github/codeql-action", true},
		{"github/codeql-action/analyze@v3", "github/codeql-action/analyze", true},
		{"github/codeql-action/init@v3", "github/codeql-action/analyze", false},
		// local actions and Docker images are not remote actions
		{"./actions/checkout", "actions/checkout", false},
		{"$/actions/checkout", "actions/checkout", false},
		{"docker://actions/checkout:latest", "actions/checkout", false},
		// ambiguous references do not match
		{"checkout@v4", "actions/checkout", false},
	}

	for _, tt := range tests {
		t.Run(tt.spec+" vs "+tt.action, func(t *testing.T) {
			if got := ParseActionRef(tt.spec).Is(tt.action); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
