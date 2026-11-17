package rules

import (
	"strings"
	"testing"

	"github.com/rhysd/actionlint"
)

// artefactErrors runs the rule on src the way the visitor of actionlint does: workflow, then every
// job with its steps, then the workflow again for the cross-job chain.
func artefactErrors(t *testing.T, src string) []*actionlint.Error {
	t.Helper()

	w, perr := actionlint.Parse([]byte(src))
	if len(perr) != 0 {
		t.Fatal(perr)
	}

	rule := NewRuleRuleDangerousArtefact(nil)

	if err := rule.VisitWorkflowPre(w); err != nil {
		t.Fatal(err)
	}

	for _, job := range w.Jobs {
		if err := rule.VisitJobPre(job); err != nil {
			t.Fatal(err)
		}

		for _, s := range job.Steps {
			if err := rule.VisitStep(s); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := rule.VisitWorkflowPost(w); err != nil {
		t.Fatal(err)
	}

	return rule.Errs()
}

// twoJobs builds a workflow with a producer job and a consumer job (steps already indented).
func twoJobs(producer, consumer string) string {
	return "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" + producer +
		"  deploy:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    needs: build\n" +
		"    steps:\n" + consumer
}

func TestRuleDangerousArtefactChain(t *testing.T) {
	upload := "      - uses: actions/checkout@v4\n" +
		"      - uses: actions/upload-artifact@v4\n" +
		"        with:\n" +
		"          name: workspace\n" +
		"          path: .\n"
	download := "      - uses: actions/download-artifact@v4\n" +
		"        with:\n" +
		"          name: workspace\n"

	tests := []struct {
		name string
		src  string
		want int
	}{
		{"upload and download by name", twoJobs(upload, download+"      - run: ./run.sh\n"), 2},
		{"download of every artifact", twoJobs(upload, "      - uses: actions/download-artifact@v4\n      - run: ls\n"), 2},
		{"download of another artifact", twoJobs(upload, strings.Replace(download, "workspace", "other", 2)), 1},
		{"normal test artifact", twoJobs(
			"      - uses: actions/upload-artifact@v4\n        with:\n          name: dist\n          path: dist/\n",
			"      - uses: actions/download-artifact@v4\n        with:\n          name: dist\n      - run: make test\n"), 0},
		{"download pinned to a commit", twoJobs(upload,
			"      - uses: dawidd6/action-download-artifact@v6\n        with:\n          name: workspace\n          commit: 0123456789abcdef0123456789abcdef01234567\n      - run: ./run.sh\n"), 1},
		{"no download", twoJobs(upload, "      - run: make\n"), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(artefactErrors(t, tt.src)); got != tt.want {
				t.Fatalf("got %d errors, want %d", got, tt.want)
			}
		})
	}
}

// The chain finding tells what the artifact carries and what the consumer does with it.
func TestRuleDangerousArtefactChainMessage(t *testing.T) {
	src := "on: push\n" +
		"jobs:\n" +
		"  build:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    permissions:\n" +
		"      contents: write\n" +
		"    steps:\n" +
		"      - uses: actions/checkout@v4\n" +
		"      - uses: actions/upload-artifact@v4\n" +
		"        with:\n" +
		"          name: workspace\n" +
		"          path: .\n" +
		"  deploy:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    needs: build\n" +
		"    permissions:\n" +
		"      id-token: write\n" +
		"    steps:\n" +
		"      - uses: actions/download-artifact@v4\n" +
		"        with:\n" +
		"          name: workspace\n" +
		"      - run: ./deploy.sh\n"

	errs := artefactErrors(t, src)
	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2", len(errs))
	}

	chain := errs[1].Message

	for _, want := range []string{"\"build\"", "\"deploy\"", "persists the credentials", "without hash verification", "executes it", "contents", "id-token"} {
		if !strings.Contains(chain, want) {
			t.Errorf("chain message %q does not contain %q", chain, want)
		}
	}
}
