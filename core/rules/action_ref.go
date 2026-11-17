package rules

import (
	"strings"
)

// SourceKind is where the code of an action comes from.
type SourceKind int

const (
	// SourceInvalid is a specification that does not parse: an ambiguous reference.
	SourceInvalid SourceKind = iota
	// SourceLocal is an action of the caller repository ("./path" or "$/path").
	SourceLocal
	// SourceDocker is an image of a registry ("docker://image:tag").
	SourceDocker
	// SourceRemote is an action of a GitHub repository ("owner/repo[/path]@ref").
	SourceRemote
)

// PinKind is how a reference fixes the code that runs.
type PinKind int

const (
	// PinNone is a missing ref: invalid for a remote action.
	PinNone PinKind = iota
	// PinMutable is a tag or a branch: the code can change under the same ref.
	PinMutable
	// PinShortSHA is all hexadecimal but not a full commit SHA: an ambiguous reference
	// (a short SHA is not a valid pin and a hex string can also be a branch or a tag).
	PinShortSHA
	// PinSHA is a full length commit SHA.
	PinSHA
	// PinDigest is the digest of a Docker image ("sha256:...").
	PinDigest
)

// ActionRef is the identity of a "uses:" specification as one fact: the source of the code,
// how it is pinned and the path actually called. The rules must reason on this fact and not on
// the raw string: "Actions/Checkout@v4", "actions/checkout@11bd719" and
// "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" are the same source with
// different strings, and GitHub resolves repository names case-insensitively (a rename or a
// different case redirects to the same, possibly third-party, repository).
type ActionRef struct {
	Raw   string     // the specification as written
	Kind  SourceKind // where the code comes from
	Owner string     // owner of the repository (SourceRemote)
	Repo  string     // name of the repository (SourceRemote)
	Path  string     // path of the action inside the repository, empty at the root
	Ref   string     // git ref, image tag or digest
	Pin   PinKind    // how Ref fixes the code
}

// ParseActionRef parses a "uses:" specification into its identity. It never fails: what cannot
// be parsed cleanly is reported as SourceInvalid or with an ambiguous pin so the callers can
// fail closed.
func ParseActionRef(spec string) ActionRef {
	ref := ActionRef{Raw: spec}

	if isLocalRef(spec) {
		ref.Kind = SourceLocal
		ref.Path = spec

		return ref
	}

	if image, ok := strings.CutPrefix(spec, "docker://"); ok {
		ref.Kind = SourceDocker
		ref.Path, ref.Ref, ref.Pin = parseImage(image)

		return ref
	}

	// "{owner}/{repo}[/path]@{ref}", the ref is cut at the first "@" like actionlint does
	path, gitRef, hasRef := strings.Cut(spec, "@")

	owner, rest, hasOwner := strings.Cut(path, "/")
	repo, subPath, _ := strings.Cut(rest, "/")

	if !hasOwner || owner == "" || repo == "" {
		ref.Kind = SourceInvalid

		return ref
	}

	ref.Kind = SourceRemote
	ref.Owner = owner
	ref.Repo = repo
	ref.Path = subPath
	ref.Ref = gitRef
	ref.Pin = classifyGitRef(gitRef, hasRef)

	return ref
}

// Is reports whether the action is the action "owner/repo[/path]" (case-insensitive). The
// repository is the identity: the ref never changes it, and a reference without a path matches
// any path of the repository (a monorepo keeps the source of its actions). An entry with a path
// only matches that path of the repository.
func (r ActionRef) Is(action string) bool {
	if r.Kind != SourceRemote {
		return false
	}

	owner, rest, ok := strings.Cut(action, "/")
	if !ok {
		return false
	}

	repo, path, _ := strings.Cut(rest, "/")

	if !strings.EqualFold(r.Owner, owner) || !strings.EqualFold(r.Repo, repo) {
		return false
	}

	return path == "" || strings.EqualFold(r.Path, path)
}

// parseImage splits "image[:tag][@digest]". The tag is the last ":" after the last "/" so a
// registry port ("localhost:5000/image") is not one.
func parseImage(image string) (name, ref string, pin PinKind) {
	name, digest, hasDigest := strings.Cut(image, "@")
	if hasDigest {
		if isDigest(digest) {
			return name, digest, PinDigest
		}

		return name, digest, PinShortSHA
	}

	if i := strings.LastIndex(name, ":"); i >= 0 && i > strings.LastIndex(name, "/") {
		return name[:i], name[i+1:], PinMutable
	}

	return name, "", PinNone
}

// classifyGitRef tells how a git ref pins the code. Only a full length commit SHA is a pin:
// anything shorter is ambiguous and the callers must fail closed with it.
func classifyGitRef(ref string, hasRef bool) PinKind {
	if !hasRef || ref == "" {
		return PinNone
	}

	if isHex(ref) {
		if len(ref) == 40 || len(ref) == 64 {
			return PinSHA
		}

		return PinShortSHA
	}

	return PinMutable
}

func isHex(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}

	return s != ""
}

// isDigest reports whether ref looks like "sha256:<64 hex>".
func isDigest(ref string) bool {
	algo, hex, ok := strings.Cut(ref, ":")

	return ok && algo != "" && len(hex) == 64 && isHex(hex)
}
