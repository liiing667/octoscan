package core

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/common"
)

// newReportLinter builds an OctoLinter with the octoscan rules and the default ignore patterns, like the scan command.
func newReportLinter(t *testing.T) *OctoLinter {
	t.Helper()

	Internetavailable = false

	opts := &actionlint.LinterOptions{OnRulesCreated: OnRulesCreated}
	opts.IgnorePatterns = append(opts.IgnorePatterns, common.SyntaxCheckErrors...)

	l, err := actionlint.NewLinter(io.Discard, opts)
	if err != nil {
		t.Fatal(err)
	}

	return &OctoLinter{Linter: *l}
}

// statusOf maps file paths to their scan status in a report.
func statusOf(report *ScanReport) map[string]FileStatus {
	statuses := map[string]FileStatus{}

	for _, file := range report.Files {
		statuses[filepath.Base(file.Path)] = file.Status
	}

	return statuses
}

// assertStatuses checks that every file has the expected unified status.
func assertStatuses(t *testing.T, report *ScanReport, want map[string]FileStatus) {
	t.Helper()

	statuses := statusOf(report)
	for name, status := range want {
		if statuses[name] != status {
			t.Fatalf("%q: got %q, want %q (%+v)", name, statuses[name], status, statuses)
		}
	}
}

// assertCounts checks the unified counts of the report for the four statuses.
func assertCounts(t *testing.T, report *ScanReport, success, rule, parse, read int) {
	t.Helper()

	got := map[FileStatus]int{
		FileStatusSuccess:      report.Count(FileStatusSuccess),
		FileStatusRuleFailure:  report.Count(FileStatusRuleFailure),
		FileStatusParseFailure: report.Count(FileStatusParseFailure),
		FileStatusReadFailure:  report.Count(FileStatusReadFailure),
	}
	want := map[FileStatus]int{
		FileStatusSuccess:      success,
		FileStatusRuleFailure:  rule,
		FileStatusParseFailure: parse,
		FileStatusReadFailure:  read,
	}

	for status, count := range want {
		if got[status] != count {
			t.Fatalf("unexpected counts: got %+v, want %+v", got, want)
		}
	}
}

// A mixed directory must produce an auditable incomplete report: every workflow gets one status, the unreadable and
// unparsable files are listed, the findings of the other files are kept and the scan still returns no fatal error.
func TestMixedDirectoryReport(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "clean.yml"), "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	write(t, filepath.Join(dir, "vulnerable.yml"), workflowInjection)
	write(t, filepath.Join(dir, "malformed.yml"), "on: [\n")

	// a dangling symlink is listed by filepath.Glob but cannot be read
	if err := os.Symlink(filepath.Join(dir, "missing.yml"), filepath.Join(dir, "dangling.yml")); err != nil {
		t.Fatal(err)
	}

	report, err := newReportLinter(t).LintRepositoryRecurse(context.Background(), dir)
	if err != nil {
		t.Fatalf("an incomplete scan must not be a fatal error: %v", err)
	}

	if report.Cancelled {
		t.Fatal("the scan was not cancelled")
	}

	if len(report.Files) != 4 {
		t.Fatalf("got %d file results, want 4: %+v", len(report.Files), report.Files)
	}

	want := map[string]FileStatus{
		"clean.yml":      FileStatusSuccess,
		"vulnerable.yml": FileStatusRuleFailure,
		"malformed.yml":  FileStatusParseFailure,
		"dangling.yml":   FileStatusReadFailure,
	}

	assertStatuses(t, report, want)
	assertCounts(t, report, 1, 1, 1, 1)

	// the failed file list exposes the incomplete results, not the rule findings
	failed := report.FailedFiles()
	if len(failed) != 2 {
		t.Fatalf("got %d failed files, want 2: %+v", len(failed), failed)
	}

	assertFailedFiles(t, failed, "malformed.yml", "dangling.yml")

	// findings of the files that could still be scanned are preserved
	assertFindings(t, report, 1, "expression-injection")
}

// assertFailedFiles checks that exactly the given base names are reported as incomplete results, each with an error.
func assertFailedFiles(t *testing.T, failed []FileResult, names ...string) {
	t.Helper()

	got := map[string]bool{}

	for _, file := range failed {
		if file.Err == nil {
			t.Fatalf("%q is listed as failed without an error", file.Path)
		}

		got[filepath.Base(file.Path)] = true
	}

	for _, name := range names {
		if !got[name] {
			t.Fatalf("failed files are %v, want %v", got, names)
		}
	}

	if len(got) != len(names) {
		t.Fatalf("failed files are %v, want %v", got, names)
	}
}

// assertFindings checks the number of findings, optionally all of the given kind.
func assertFindings(t *testing.T, report *ScanReport, total int, kind string) {
	t.Helper()

	if len(report.Findings) != total {
		t.Fatalf("got %d findings, want %d: %+v", len(report.Findings), total, report.Findings)
	}

	if kind == "" {
		return
	}

	for _, finding := range report.Findings {
		if finding.Kind != kind {
			t.Fatalf("unexpected finding %q, want only %q: %+v", finding.Kind, kind, report.Findings)
		}
	}
}

// Parse failures stay visible even though the scan command ignores actionlint syntax-check findings.
func TestParseFailureIgnoredByPatterns(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "malformed.yml"), "on: [\n")
	write(t, filepath.Join(dir, "vulnerable.yml"), workflowInjection)

	report, err := newReportLinter(t).LintRepositoryRecurse(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	assertStatuses(t, report, map[string]FileStatus{
		"malformed.yml":  FileStatusParseFailure,
		"vulnerable.yml": FileStatusRuleFailure,
	})

	if got := report.Count(FileStatusParseFailure); got != 1 {
		t.Fatalf("got %d parse failures, want 1", got)
	}
}

// After cancellation no new workflow file is started: only the files scanned before the cancellation are reported,
// the gathered findings stay available and the scan still ends without a fatal error.
func TestCancellationStopsBeforeNextFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.yml"), workflowInjection)
	write(t, filepath.Join(dir, "b.yml"), workflowInjection)
	write(t, filepath.Join(dir, "c.yml"), workflowInjection)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := newReportLinter(t).LintRepositoryRecurse(ctx, dir)
	if err != nil {
		t.Fatalf("a cancelled scan must not be a fatal error: %v", err)
	}

	if !report.Cancelled {
		t.Fatal("the report must record the cancellation")
	}

	if len(report.Files) != 0 {
		t.Fatalf("no file was supposed to start after the cancellation, got %+v", report.Files)
	}

	if len(report.Findings) != 0 {
		t.Fatalf("no finding was expected, got %d", len(report.Findings))
	}
}

// Every workflow of a recursive scan ends in the same unified summary, including failures in different folders.
func TestRecursiveScanUnifiedSummary(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "one", ".github", "workflows", "root.yml"), workflowInjection)
	write(t, filepath.Join(root, "two", ".github", "workflows", "broken.yml"), "on: [\n")
	write(t, filepath.Join(root, "two", ".github", "workflows", "clean.yml"),
		"on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")

	report, err := newReportLinter(t).LintRepositoryRecurse(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Files) != 3 {
		t.Fatalf("got %d file results, want 3: %+v", len(report.Files), report.Files)
	}

	assertCounts(t, report, 1, 1, 1, 0)
	assertStatuses(t, report, map[string]FileStatus{
		"root.yml":   FileStatusRuleFailure,
		"broken.yml": FileStatusParseFailure,
		"clean.yml":  FileStatusSuccess,
	})

	// the finding of the first repository is kept despite the parse failure in the nested one
	assertFindings(t, report, 1, "expression-injection")
}
