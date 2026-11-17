package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousArtefact struct {
	actionlint.RuleBase
	filterTriggers       []string
	skip                 bool
	persistedCredentials bool // a checkout of the job left the token in .git/config
	jobID                string
	writeScopes          []string // effective permissions of the current job
	workflowScopes       []string
	uploads              []*artifactUpload
	downloads            []*artifactDownload
}

// paths that include the whole workspace
var sensitivePaths = []string{
	".",
	"./",
	".\\",
	"..",
	"*",
	"**",
	"./**",
	".*",
	"~",
}

// artifactUpload is the provenance of one uploaded artifact: what it contains and which token the
// producer job had when it built it.
type artifactUpload struct {
	jobID          string
	name           string // "" when the name is an expression
	broadPath      bool   // a sensitive path: the whole workspace, a glob, the home directory
	gitDir         bool   // a path that includes the .git directory
	persistedCreds bool   // a checkout of the producer job left the token in .git/config
	writeScopes    []string
}

func (u *artifactUpload) sensitive() bool {
	return u.broadPath || u.gitDir
}

// artifactDownload is one consumer of the artifacts of the run.
type artifactDownload struct {
	jobID       string
	name        string // "" downloads every artifact of the run
	pos         *actionlint.Pos
	hasHash     bool // the content is pinned (commit, checked artifacts)
	executed    bool // a run step of the job consumes the download
	writeScopes []string
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleRuleDangerousArtefact(filterTriggers []string) *RuleDangerousArtefact {
	return &RuleDangerousArtefact{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-artefact",
			"Check for workflow that upload artefacts containing sensitive files.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousArtefact) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)
	rule.workflowScopes = writeScopesOf(n.Permissions)
	rule.uploads = nil
	rule.downloads = nil

	return nil
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleDangerousArtefact) VisitJobPre(n *actionlint.Job) error {
	// reset for each job
	rule.persistedCredentials = false
	rule.jobID = n.ID.Value
	rule.writeScopes = rule.workflowScopes

	if n.Permissions != nil {
		rule.writeScopes = writeScopesOf(n.Permissions)
	}

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousArtefact) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	if run, ok := n.Exec.(*actionlint.ExecRun); ok && run.Run != nil {
		// a script of the job consumes what the previous downloads restored
		for _, d := range rule.downloads {
			if d.jobID == rule.jobID {
				d.executed = true
			}
		}

		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	switch {
	case strings.HasPrefix(spec, "actions/checkout"):
		// the token is persisted in .git/config unless it is explicitly disabled
		persist := e.Inputs["persist-credentials"]
		if persist == nil || !strings.EqualFold(strings.TrimSpace(persist.Value.Value), "false") {
			rule.persistedCredentials = true
		}
	case strings.HasPrefix(spec, "actions/upload-artifact"):
		rule.checkUpload(e)
	case strings.HasPrefix(spec, "actions/download-artifact"):
		rule.downloads = append(rule.downloads, rule.newDownload(e, false))
	case strings.HasPrefix(spec, "dawidd6/action-download-artifact"):
		// "commit" pins the run to download from, "check_artifacts" rejects artifacts not
		// produced by the checked workflows: the content is not picked by name only
		rule.downloads = append(rule.downloads, rule.newDownload(e, true))
	}

	return nil
}

func (rule *RuleDangerousArtefact) newDownload(e *actionlint.ExecAction, hashInputs bool) *artifactDownload {
	d := &artifactDownload{
		jobID:       rule.jobID,
		pos:         e.Uses.Pos,
		writeScopes: rule.writeScopes,
	}

	if name := e.Inputs["name"]; name != nil && !containsExpression(name.Value.Value) {
		d.name = strings.TrimSpace(name.Value.Value)
		d.pos = name.Value.Pos
	}

	if hashInputs {
		if commit := e.Inputs["commit"]; commit != nil && strings.TrimSpace(commit.Value.Value) != "" {
			d.hasHash = true
		}

		if check := e.Inputs["check_artifacts"]; check != nil && strings.EqualFold(strings.TrimSpace(check.Value.Value), "true") {
			d.hasHash = true
		}
	}

	return d
}

// ponytail: upload-artifact v4 skips hidden files by default so a broad path only leaks .git with
// include-hidden-files, we report it anyway, narrow down if it is too noisy.
func (rule *RuleDangerousArtefact) checkUpload(e *actionlint.ExecAction) {
	upload := &artifactUpload{
		jobID:          rule.jobID,
		name:           "artifact", // default name of actions/upload-artifact
		persistedCreds: rule.persistedCredentials,
		writeScopes:    rule.writeScopes,
	}

	if name := e.Inputs["name"]; name != nil {
		if containsExpression(name.Value.Value) {
			upload.name = ""
		} else {
			upload.name = strings.TrimSpace(name.Value.Value)
		}
	}

	path := e.Inputs["path"]
	if path == nil {
		rule.uploads = append(rule.uploads, upload)

		return
	}

	offset := 0 // of the line in the value

	for _, line := range strings.Split(path.Value.Value, "\n") {
		p := strings.TrimSpace(line)
		pos := posInString(path.Value.Value, path.Value.Pos, path.Value.Quoted, offset+strings.Index(line, p))
		offset += len(line) + 1

		switch {
		case p == "" || strings.HasPrefix(p, "!"):
		case includesGitDir(p):
			upload.gitDir = true

			rule.Errorf(
				pos,
				"Use of action 'actions/upload-artifact' with a path including the .git directory %q%s",
				p,
				rule.credentialsNote(),
			)
		case slices.Contains(sensitivePaths, p):
			upload.broadPath = true

			rule.Errorf(
				pos,
				"Use of action 'actions/upload-artifact' with a sensitive path %q%s",
				p,
				rule.credentialsNote(),
			)
		}
	}

	rule.uploads = append(rule.uploads, upload)
}

func (rule *RuleDangerousArtefact) credentialsNote() string {
	if rule.persistedCredentials {
		return ", a previous checkout persists the credentials in .git/config (set \"persist-credentials: false\")"
	}

	return ""
}

func includesGitDir(p string) bool {
	return slices.Contains(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }), ".git")
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children: the uploads
// and the downloads of every job are known, the artifact chain can be checked.
func (rule *RuleDangerousArtefact) VisitWorkflowPost(n *actionlint.Workflow) error {
	if rule.skip {
		return nil
	}

	for _, d := range rule.downloads {
		if d.hasHash {
			continue
		}

		for _, u := range rule.uploads {
			if !u.sensitive() || u.jobID == d.jobID {
				continue
			}

			// a download without a name fetches every artifact of the run
			if d.name != "" && u.name != "" && d.name != u.name {
				continue
			}

			rule.Errorf(
				d.pos,
				"Artifact %q uploaded by job %q (%s) is downloaded by job %q without hash verification%s%s",
				u.name,
				u.jobID,
				u.contentNote(),
				d.jobID,
				d.consumerNote(),
				u.tokenNote(),
			)
		}
	}

	return nil
}

// contentNote is the provenance of the artifact: what the upload put in it.
func (u *artifactUpload) contentNote() string {
	what := "a broad path"
	if u.gitDir {
		what = "the .git directory"
	}

	if u.persistedCreds {
		return what + ", the checkout of the job persists the credentials in .git/config"
	}

	return what
}

// tokenNote is the producer side of the chain: the permissions the leaked token keeps.
func (u *artifactUpload) tokenNote() string {
	if !u.persistedCreds || len(u.writeScopes) == 0 {
		return ""
	}

	return fmt.Sprintf(", the persisted token keeps the write permissions of the job (%s)", strings.Join(u.writeScopes, ", "))
}

// consumerNote is the consumer side of the chain: what the downloading job does with the artifact.
func (d *artifactDownload) consumerNote() string {
	var notes []string

	if d.executed {
		notes = append(notes, "executes it")
	}

	if len(d.writeScopes) > 0 {
		notes = append(notes, fmt.Sprintf("holds write permissions (%s)", strings.Join(d.writeScopes, ", ")))
	}

	if len(notes) == 0 {
		return ""
	}

	return " and " + strings.Join(notes, " and ")
}

// writeScopesOf returns the names of the scopes set to "write", sorted for stable messages.
func writeScopesOf(p *actionlint.Permissions) []string {
	if p == nil {
		return nil
	}

	if p.All != nil {
		if strings.EqualFold(p.All.Value, "write-all") {
			return []string{"write-all"}
		}

		return nil
	}

	var scopes []string

	for name, scope := range p.Scopes {
		if scope.Value != nil && strings.EqualFold(scope.Value.Value, "write") {
			scopes = append(scopes, name)
		}
	}

	slices.Sort(scopes)

	return scopes
}
