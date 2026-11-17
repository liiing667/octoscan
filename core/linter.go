package core

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/synacktiv/octoscan/common"
	"github.com/synacktiv/octoscan/core/rules"

	"github.com/rhysd/actionlint"
)

type OctoLinter struct {
	actionlint.Linter
	// OnFile is called with the errors of each file as soon as it is linted, to display them as the scan goes (optional).
	OnFile func([]*actionlint.Error)
}

// FileStatus is the outcome of scanning one workflow file.
type FileStatus string

const (
	// FileStatusSuccess: the workflow was parsed and scanned, no finding and no failure.
	FileStatusSuccess FileStatus = "success"
	// FileStatusParseFailure: the workflow could not be parsed, rule findings it may still carry are kept.
	FileStatusParseFailure FileStatus = "parse-failure"
	// FileStatusRuleFailure: the workflow was parsed and one or more rules raised findings.
	FileStatusRuleFailure FileStatus = "rule-failure"
	// FileStatusReadFailure: the file could not be read, no finding is available for it.
	FileStatusReadFailure FileStatus = "read-failure"
)

// FileResult summarizes the scan of one workflow file.
type FileResult struct {
	Path   string
	Status FileStatus
	// Err is the non-fatal error that made the result incomplete (read or lint failure), nil otherwise.
	Err error
	// Findings raised for the file, kept even when the file failed to parse completely.
	Findings []*actionlint.Error
}

// ScanReport aggregates the outcome of every workflow file of a directory scan. A scan that could not read or parse
// some files is incomplete but not fatal: Err stays nil and the findings of the other files are still reported.
type ScanReport struct {
	Files     []FileResult
	Findings  []*actionlint.Error
	Cancelled bool
	// Err is set only for failures that are not attached to a file (a workflow folder that cannot be walked).
	Err error
}

// Count returns how many files ended in the given status.
func (r *ScanReport) Count(status FileStatus) int {
	count := 0

	for _, file := range r.Files {
		if file.Status == status {
			count++
		}
	}

	return count
}

// FailedFiles returns the files whose result is incomplete: unreadable or unparsable files, and files a rule could
// not run on. Files that only carry rule findings are not failures.
func (r *ScanReport) FailedFiles() []FileResult {
	var failed []FileResult

	for _, file := range r.Files {
		if file.Status == FileStatusReadFailure || file.Status == FileStatusParseFailure || file.Err != nil {
			failed = append(failed, file)
		}
	}

	return failed
}

// not optimal but I can't pass other parameters to OnRulesCreated
var (
	FilterTriggers    = []string{}
	FilterRun         = false
	Internetavailable = true
	DebugRules        = false
	RulesSwitch       = map[string]bool{
		"dangerous-action":        true,
		"dangerous-checkout":      true,
		"expression-injection":    true,
		"dangerous-write":         true,
		"local-action":            true,
		"repo-jacking":            true,
		"shellcheck":              true,
		"credentials":             true,
		"runner-label":            true,
		"dangerous-artefact":      true,
		"unsecure-commands":       true,
		"known-vulnerability":     true,
		"bot-check":               true,
		"overprovisioned-secrets": true,
		"toctou":                  true,
		"prompt-injection":        true,
		"unsound-condition":       true,
		"debug-external-trigger":  true,
		"debug-artefacts":         true,
		"debug-js-exec":           true,
		"debug-oidc-action":       true,
	}
)

func FilterRules(include bool, rulesFiltered []string) {
	for name := range RulesSwitch {
		RulesSwitch[name] = (include == slices.Contains(rulesFiltered, name))
	}
}

func OnRulesCreated(rules []actionlint.Rule) []actionlint.Rule {
	res := filterUnWantedRules(rules)
	res = append(res, offlineRules()...)

	if Internetavailable {
		res = append(res, onlineRules()...)
	}

	return res
}

func filterUnWantedRules(rules []actionlint.Rule) []actionlint.Rule {
	res := []actionlint.Rule{}

	for _, r := range rules {
		// only keep credential and shellcheck rule
		if r.Name() == "credentials" && RulesSwitch["credentials"] {
			res = append(res, r)
		}

		if r.Name() == "shellcheck" && RulesSwitch["shellcheck"] {
			res = append(res, r)
		}

		// if r.Name() == "runner-label" && rulesSwitch["runner-label"] {
		// 	res = append(res, r)
		// }
	}

	/*
		if no rules are passed this function is called from octosan
		so we can add dummy rules for the --list-rule option and for the sarif format.
	*/
	if len(rules) == 0 {
		res = append(res, &actionlint.RuleCredentials{RuleBase: actionlint.NewRuleBase("shellcheck", "Checks for shell script sources in \"run:\" using shellcheck")})
		res = append(res, &actionlint.RuleShellcheck{RuleBase: actionlint.NewRuleBase("credentials", "Checks for credentials in \"services:\" configuration")})
	}

	return res
}

func offlineRules() []actionlint.Rule {

	var res = []actionlint.Rule{}

	if RulesSwitch["dangerous-action"] {
		res = append(res, rules.NewRuleDangerousAction(FilterTriggers))
	}

	if RulesSwitch["dangerous-checkout"] {
		res = append(res, rules.NewRuleDangerousCheckout(FilterTriggers))
	}

	if RulesSwitch["expression-injection"] {
		res = append(res, rules.NewRuleExpressionInjection(FilterTriggers, FilterRun))
	}

	if RulesSwitch["dangerous-write"] {
		res = append(res, rules.NewRuleDangerousWrite(FilterTriggers))
	}

	if RulesSwitch["local-action"] {
		res = append(res, rules.NewRuleLocalAction(FilterTriggers))
	}

	if RulesSwitch["runner-label"] {
		res = append(res, rules.NewRuleRunnerLabel())
	}

	if RulesSwitch["unsecure-commands"] {
		res = append(res, rules.NewRuleUnsecureCommands(FilterTriggers))
	}

	if RulesSwitch["known-vulnerability"] {
		res = append(res, rules.NewRuleKnownVulnerability(FilterTriggers))
	}

	if RulesSwitch["bot-check"] {
		res = append(res, rules.NewRuleBotCheck(FilterTriggers))
	}

	if RulesSwitch["dangerous-artefact"] {
		// run on every trigger even if specified by the user because this vulnerability
		// can be triggered in every workflow
		res = append(res, rules.NewRuleRuleDangerousArtefact(common.AllTriggers))
	}

	if RulesSwitch["toctou"] {
		res = append(res, rules.NewRuleToctou(FilterTriggers))
	}

	if RulesSwitch["prompt-injection"] {
		res = append(res, rules.NewRulePromptInjection(FilterTriggers))
	}

	if RulesSwitch["unsound-condition"] {
		res = append(res, rules.NewRuleUnsoundCondition(FilterTriggers))
	}

	if RulesSwitch["overprovisioned-secrets"] {
		// every trigger: a dumped secret context is exposed whatever starts the workflow
		res = append(res, rules.NewRuleOverprovisionedSecrets(common.AllTriggers))
	}

	if DebugRules {
		if RulesSwitch["debug-external-trigger"] {
			res = append(res, rules.NewRuleDebugExternalTrigger(FilterTriggers))
		}

		if RulesSwitch["debug-artefacts"] {
			res = append(res, rules.NewRuleRuleDebugArtefacts(FilterTriggers))
		}

		if RulesSwitch["debug-js-exec"] {
			res = append(res, rules.NewRuleDebugJSExec(FilterTriggers))
		}

		if RulesSwitch["debug-oidc-action"] {
			res = append(res, rules.NewRuleOIDCAction())
		}
	}

	return res
}

func onlineRules() []actionlint.Rule {
	var res = []actionlint.Rule{}

	if RulesSwitch["repo-jacking"] {
		res = append(res, rules.NewRuleRepoJacking())
	}

	return res
}

// lintFile scans one workflow file and never returns a fatal error: a file that cannot be read or parsed is recorded
// in the returned FileResult so the scan can keep going with the other files. Parse failures are detected before the
// octoscan ignore patterns are applied, otherwise actionlint silently filters the syntax errors away.
func (l *OctoLinter) lintFile(path string) FileResult {
	result := FileResult{Path: path, Status: FileStatusSuccess}

	src, err := os.ReadFile(path)
	if err != nil {
		result.Status = FileStatusReadFailure
		result.Err = fmt.Errorf("could not read %q: %w", path, err)

		return result
	}

	_, parseErrors := actionlint.Parse(src)

	errs, err := l.Lint(path, src, nil)
	if err != nil {
		// the other files are still worth scanning
		result.Status = FileStatusRuleFailure
		result.Err = fmt.Errorf("could not scan %q: %w", path, err)

		return result
	}

	result.Findings = errs

	switch {
	case len(parseErrors) > 0:
		// the parse failure is auditable even when its syntax errors are ignored by the configured patterns
		result.Status = FileStatusParseFailure
		result.Err = fmt.Errorf("%q could not be parsed: %d syntax error(s)", path, len(parseErrors))
	case len(errs) > 0:
		result.Status = FileStatusRuleFailure
	}

	return result
}

// lintFolder lints the YAML files of a folder one by one, calling OnFile after each. A file that fails does not stop
// the scan: it is recorded in the report and the following files are still scanned. When ctx is cancelled, the file
// currently being scanned finishes but no new file is started.
func (l *OctoLinter) lintFolder(ctx context.Context, folder string, report *ScanReport) {
	var files []string

	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(folder, pattern))
		if err != nil {
			report.Err = fmt.Errorf("could not list workflows in %q: %w", folder, err)

			return
		}

		files = append(files, matches...)
	}

	sort.Strings(files)

	for _, file := range files {
		if err := ctx.Err(); err != nil {
			report.Cancelled = true

			return
		}

		result := l.lintFile(file)

		if result.Err != nil {
			common.Log.Error(result.Err)
		}

		if l.OnFile != nil && len(result.Findings) > 0 {
			l.OnFile(result.Findings)
		}

		report.Files = append(report.Files, result)
		report.Findings = append(report.Findings, result.Findings...)
	}
}

// LintRepositoryRecurse searches for all GitHub projects recursively and runs the linter on their workflow folders.
// The returned report is an auditable, possibly incomplete result: files that cannot be read or parsed are recorded
// in it and the scan continues, and the returned error stays nil. Cancellation stops the scan before the next file is
// started, leaving the findings gathered so far in the report.
func (l *OctoLinter) LintRepositoryRecurse(ctx context.Context, dir string) (*ScanReport, error) {
	report := &ScanReport{}

	found := false

	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// record the unreadable entry and keep walking the rest of the tree
			report.Files = append(report.Files, FileResult{
				Path:   path,
				Status: FileStatusReadFailure,
				Err:    fmt.Errorf("could not read %q: %w", path, err),
			})

			return nil
		}

		w := filepath.Join(path, ".github", "workflows")
		if s, statErr := os.Stat(w); statErr == nil && s.IsDir() {
			found = true

			l.lintFolder(ctx, w, report)

			return fs.SkipDir
		}

		return nil
	}); err != nil {
		report.Err = fmt.Errorf("could not read files in %q: %w", dir, err)
	}

	if report.Cancelled {
		return report, nil
	}

	// no workflows in a folder that is not a repository: it is a folder of workflows. The root of a repository without
	// workflows has none, its other YAML files (compose files, charts...) are not workflows.
	if _, err := os.Stat(filepath.Join(dir, ".git")); !found && err != nil {
		l.lintFolder(ctx, dir, report)
	}

	return report, nil
}

/*
Everything is stolen from here: https://github.com/rhysd/actionlint/blob/main/docs/usage.md#format
Again thanks @rhysd for the great work.
*/
func DisplayErrors(writer io.Writer, format string, errs []*actionlint.Error) error {
	formatter, err := actionlint.NewErrorFormatter(format)
	rules := &[]actionlint.Rule{}
	availableRules := OnRulesCreated(*rules)

	for _, rule := range availableRules {
		formatter.RegisterRule(rule)
	}

	if err != nil {
		return err
	}

	temp := make([]*actionlint.ErrorTemplateFields, 0, len(errs))

	for _, octoscanErr := range errs {
		src, _ := os.ReadFile(octoscanErr.Filepath)
		temp = append(temp, octoscanErr.GetTemplateFields(src))
	}

	return formatter.Print(writer, temp)
}
