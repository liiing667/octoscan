package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/synacktiv/octoscan/common"
	"github.com/synacktiv/octoscan/core"

	"github.com/docopt/docopt-go"
	"github.com/fatih/color"
	"github.com/rhysd/actionlint"
)

var usageScan = `octoscan

Usage:
	octoscan scan [options] --list-rules
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--debug-rules --filter-triggers=<triggers> --filter-run --ignore=<pattern> ((--disable-rules | --enable-rules ) <rules>) --config-file <config>]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose
	--format <format>  				Output format, json, sarif or custom template to format error messages in Go template syntax. See https://github.com/rhysd/actionlint/tree/main/docs/usage.md#format
	--oneline  					Use one line per one error. Useful for reading error messages from programs

Args:
	<target>					Target File or directory to scan
	--filter-triggers <triggers>			Scan workflows with specific triggers (comma separated list: "push,pull_request_target" or pre-configured: external/allnopr)
	--filter-run					Search for expression injection only in run shell scripts.
	--ignore <pattern>				Regular expression matching to error messages you want to ignore.
	--disable-rules <rules>				Disable specific rules. Split on ","
	--enable-rules <rules>				Enable specific rules, this will disable all other rules. Split on ","
	--debug-rules					Enable debug rules.
	--config-file <config>				Config file.

Examples:
	$ octoscan scan ci.yml --disable-rules shellcheck,local-action --filter-triggers external
`

func checkInternet(args docopt.Opts) {
	checkInternet := true

	if args["--enable-rules"] != false && !strings.Contains(args["<rules>"].(string), "repo-jacking") {
		checkInternet = false
	}

	if args["--disable-rules"] != false && strings.Contains(args["<rules>"].(string), "repo-jacking") {
		checkInternet = false
	}

	if checkInternet {
		err := common.IsInternetAvailable()
		if err != nil {
			common.Log.Info("Could not connect to Internet, skipping \"repo-jacking\" rule.")

			core.Internetavailable = false
		}
	}
}

func runScanner(args docopt.Opts) int {
	var errs []*actionlint.Error
	opts := setScannerArgs(args)

	checkInternet(args)

	l, err := actionlint.NewLinter(os.Stdout, &opts)
	if err != nil {
		return common.ExitStatusFailure
	}

	file, _ := args.String("<target>")

	// the default output is displayed as the scan goes, the other formats need all the errors
	streamed := args["--format"] == nil

	if common.IsDirectory(file) {
		errs, err = scanDirectory(l, file, streamed, opts.Oneline)
	} else {
		errs, err = l.LintFile(file, nil)
	}

	if err != nil {
		common.Log.Error(err)

		return common.ExitStatusFailure
	}

	err = renderFindings(args, file, streamed, errs, opts)

	if err != nil {
		common.Log.Error(err)

		return common.ExitStatusFailure
	}

	if len(errs) > 0 {
		return common.ExitStatusSuccessProblemFound // Linter found some issues, yay!
	}

	return common.ExitStatusSuccessNoProblem
}

// renderFindings prints the findings, streamed as the scan goes for the default format or all at once otherwise.
func renderFindings(args docopt.Opts, file string, streamed bool, errs []*actionlint.Error,
	opts actionlint.LinterOptions) error {
	if streamed {
		if !common.IsDirectory(file) {
			core.FixPositions(errs)
			printErrors(os.Stdout, errs, opts.Oneline)
		}

		return nil
	}

	core.FixPositions(errs)

	switch format := args["--format"].(string); format {
	case "json":
		opts.Format = "{{json .}}"
	case "sarif":
		opts.Format = string(common.SarifTemplate)
	default:
		opts.Format = format
	}
	// Now we can use our own formatter on all the errors.
	return core.DisplayErrors(os.Stdout, opts.Format, errs)
}

// scanDirectory runs a recursive, interruptible scan of a directory and returns the gathered findings together with
// the auditable summary of every workflow file.
func scanDirectory(l *actionlint.Linter, dir string, streamed bool, oneline bool) ([]*actionlint.Error, error) {
	octoLinter := &core.OctoLinter{Linter: *l}
	if streamed {
		octoLinter.OnFile = func(batch []*actionlint.Error) {
			core.FixPositions(batch)
			printErrors(os.Stdout, batch, oneline)
		}
	}

	// the first interrupt asks for a graceful stop: the file being scanned finishes but no new file is started,
	// a second interrupt terminates the process
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		signal.Stop(signals)
		cancel()
	}()

	go func() {
		if _, ok := <-signals; ok {
			common.Log.Info("interrupted, finishing the current workflow and stopping the scan")
			cancel()
		}
	}()

	report, err := octoLinter.LintRepositoryRecurse(ctx, dir)

	printScanSummary(report)

	return report.Findings, err
}

// printScanSummary makes an incomplete directory scan auditable: every workflow file is accounted for with one
// unified status (success, parse failure, rule failure or read failure) and the files whose result is incomplete
// are listed. Such a scan still succeeds, so the SARIF output and the exit code only reflect the findings.
func printScanSummary(report *core.ScanReport) {
	if report == nil {
		return
	}

	if report.Cancelled {
		common.Log.Info("scan was cancelled: the report only contains the workflows scanned before the interruption")
	}

	common.Log.Info(fmt.Sprintf(
		"scan summary: %d workflow(s): %d success, %d rule failure(s), %d parse failure(s), %d read failure(s)",
		len(report.Files),
		report.Count(core.FileStatusSuccess),
		report.Count(core.FileStatusRuleFailure),
		report.Count(core.FileStatusParseFailure),
		report.Count(core.FileStatusReadFailure),
	))

	for _, file := range report.FailedFiles() {
		common.Log.Error(fmt.Sprintf("%s: %s: %v", file.Status, file.Path, file.Err))
	}
}

// printErrors prints the errors like actionlint does.
func printErrors(w io.Writer, errs []*actionlint.Error, oneline bool) {
	for _, e := range errs {
		var src []byte
		if !oneline {
			src, _ = os.ReadFile(e.Filepath)
		}

		e.PrettyPrint(w, src)
	}
}

func listRules() int {
	yellow := color.New(color.FgYellow)
	core.DebugRules = true
	rules := &[]actionlint.Rule{}

	common.Log.Info("Available rules")

	availableRules := core.OnRulesCreated(*rules)
	for _, rule := range availableRules {
		//nolint
		fmt.Printf("- %v\n", yellow.Sprint(rule.Name()))
		//nolint
		fmt.Printf("\t%v\n", rule.Description())
	}

	return common.ExitStatusSuccessNoProblem
}

func setCoreParameter(args docopt.Opts) {
	if args["--filter-triggers"] != nil {
		if args["--filter-triggers"].(string) == "external" {
			core.FilterTriggers = common.TriggerWithExternalData
		} else if args["--filter-triggers"].(string) == "allnopr" {
			core.FilterTriggers = common.AllTriggers
		} else {
			core.FilterTriggers = strings.Split(args["--filter-triggers"].(string), ",")
		}
	}

	if v, _ := args.Bool("--disable-rules"); v {
		core.FilterRules(false, strings.Split(args["<rules>"].(string), ","))
	}

	if v, _ := args.Bool("--enable-rules"); v {
		core.FilterRules(true, strings.Split(args["<rules>"].(string), ","))
	}

	if v, _ := args.Bool("--debug-rules"); v {
		core.DebugRules = true
	}

	if v, _ := args.Bool("--filter-run"); v {
		core.FilterRun = true
	}
}

func setScannerArgs(args docopt.Opts) actionlint.LinterOptions {
	var opts actionlint.LinterOptions

	if d, _ := args.Bool("--debug"); d {
		opts.Debug = true
	}

	if v, _ := args.Bool("--verbose"); v {
		opts.Verbose = true
	}

	if v, _ := args.Bool("--oneline"); v {
		opts.Oneline = true
	}

	/*
		This is a hacky trick to disable the formatter of actionlint otherwise it will use
		a new formatter for each repo and this not what we want. We want to use the same
		formatter for all the repo. It's far from being perfect but I don't know how to do it.
	*/
	// octoscan prints the errors itself: their positions are fixed with the source first (see core.FixPositions)
	opts.Format = "{{\"\"}}"

	setCoreParameter(args)

	opts.Shellcheck = "shellcheck"
	// Add default ignore pattern
	// by default actionlint add error when parsing Workflows files
	opts.IgnorePatterns = append(opts.IgnorePatterns, common.SyntaxCheckErrors...)

	if args["--ignore"] != nil {
		opts.IgnorePatterns = append(opts.IgnorePatterns, args["--ignore"].(string))
	}

	opts.LogWriter = os.Stderr
	opts.OnRulesCreated = core.OnRulesCreated

	if args["--config-file"] != false {
		opts.ConfigFile = args["<config>"].(string)
	}

	return opts
}

func Scan(inputArgs []string) int {
	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usageScan, inputArgs, "")

	// debug
	// common.Log.Info(args)

	if v, _ := args.Bool("--list-rules"); v {
		return listRules()
	}

	return runScanner(args)

}
