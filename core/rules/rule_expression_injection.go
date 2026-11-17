/*
the MIT License

Copyright (c) 2021 rhysd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*
this is a copy of https://github.com/rhysd/actionlint/blob/main/rule_expression.go
I need to add new UntrustedInput and check for expression injection in some fields but not all.
*/

package rules

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

// stepOutputKey identifies one output of one step for the taint memoization.
type stepOutputKey struct {
	step *actionlint.Step
	name string
}

// evalScope is the scope in which an expression is evaluated: the environment variables of the workflow, of job
// and of step are visible, as well as the outputs of the steps of job.
type evalScope struct {
	job  *actionlint.Job
	step *actionlint.Step
}

type RuleExpressionInjection struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	filterRun      bool

	// taint tracking state, reset on each workflow
	callInputs    []string // names of the string inputs of the workflow_call trigger
	workflowEnv   *actionlint.Env
	jobs          map[string]*actionlint.Job
	job           *actionlint.Job  // job being visited
	step          *actionlint.Step // step being visited
	stepWrites    map[*actionlint.Step]map[string][]string
	taintMemo     map[any]bool
	taintVisiting map[any]bool
}

// NewRuleExpressionInjection creates new RuleExpressionInjection instance.
func NewRuleExpressionInjection(filterTriggers []string, filterRun bool) *RuleExpressionInjection {
	return &RuleExpressionInjection{
		RuleBase: actionlint.NewRuleBase(
			"expression-injection",
			"Check for expression injection.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
		filterRun:      filterRun,
	}
}

func (rule *RuleExpressionInjection) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	// the inputs of a workflow_call trigger are controlled by the caller: they are as untrusted as the data the
	// caller passes, which may come from the event
	rule.callInputs = nil

	for _, e := range n.On {
		call, ok := e.(*actionlint.WorkflowCallEvent)
		if !ok {
			continue
		}

		for _, i := range call.Inputs {
			// only string inputs can carry an injection, booleans and numbers are coerced
			if i.Name != nil && (i.Type == actionlint.WorkflowCallEventInputTypeString || i.Type == actionlint.WorkflowCallEventInputTypeInvalid) {
				rule.callInputs = append(rule.callInputs, i.Name.Value)
			}
		}
	}

	rule.workflowEnv = n.Env
	rule.jobs = n.Jobs
	rule.job = nil
	rule.step = nil
	rule.stepWrites = map[*actionlint.Step]map[string][]string{}
	rule.taintMemo = map[any]bool{}
	rule.taintVisiting = map[any]bool{}

	return nil
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleExpressionInjection) VisitJobPre(n *actionlint.Job) error {

	rule.job = n
	rule.step = nil

	if n.Services != nil {
		for _, s := range n.Services.Value {
			rule.checkContainer(s.Container, "jobs.<job_id>.services", "<service_id>")
		}
	}

	return nil
}

// VisitJobPost is callback when visiting Job node after visiting its children.
func (rule *RuleExpressionInjection) VisitJobPost(n *actionlint.Job) error {
	rule.job = nil
	rule.step = nil

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleExpressionInjection) VisitStep(n *actionlint.Step) error {

	rule.step = n

	if rule.skip {
		return nil
	}

	// rule.checkString(n.Name, "jobs.<job_id>.steps.name")

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkString(e.Run, "jobs.<job_id>.steps.run")
		// rule.checkString(e.Shell, "")
		rule.checkString(e.WorkingDirectory, "jobs.<job_id>.steps.working-directory")
	case *actionlint.ExecAction:

		if !rule.filterRun {
			rule.checkString(e.Uses, "")

			for _, i := range e.Inputs {
				rule.checkString(i.Value, "jobs.<job_id>.steps.with")
			}

			rule.checkString(e.Entrypoint, "")
			rule.checkString(e.Args, "")
		} else {
			if script := e.Inputs["script"]; script != nil && strings.HasPrefix(e.Uses.Value, "actions/github-script") {
				rule.checkString(script.Value, "jobs.<job_id>.steps.with")
			}
		}

	}

	// rule.checkEnv(n.Env, "jobs.<job_id>.steps.env") // env: at step level can refer 'env' context (#158)

	// if n.ID != nil {
	// 	if n.ID.ContainsExpression() {
	// 		rule.checkString(n.ID, "")
	// 	}
	// }

	return nil
}

// I merged checkString and checkScriptString for now
func (rule *RuleExpressionInjection) checkString(str *actionlint.String, workflowKey string) {
	if str == nil {
		return
	}

	rule.checkExprsIn(str.Value, str.Pos, str.Quoted, true, workflowKey)
}

func (rule *RuleExpressionInjection) checkEnv(env *actionlint.Env, workflowKey string) {
	if env == nil {
		return
	}

	if env.Vars != nil {
		for _, e := range env.Vars {
			rule.checkString(e.Name, workflowKey)
			rule.checkString(e.Value, workflowKey)
		}
		return
	}
}

func (rule *RuleExpressionInjection) checkExprsIn(s string, pos *actionlint.Pos, quoted, checkUntrusted bool, workflowKey string) {
	value := s
	offset := 0 // of s in value

	for {
		idx := strings.Index(s, "${{")
		if idx == -1 {
			break
		}

		start := idx + 3 // 3 means removing "${{"
		s = s[start:]
		offset += start

		p := posInString(value, pos, quoted, offset)

		offsetAfter, ok := rule.checkSemantics(s, p.Line, p.Col, checkUntrusted, workflowKey)
		if !ok {
			return
		}

		s = s[offsetAfter:]
		offset += offsetAfter
	}
}

func (rule *RuleExpressionInjection) checkSemantics(src string, line, col int, checkUntrusted bool, workflowKey string) (int, bool) {
	l := actionlint.NewExprLexer(src)
	p := actionlint.NewExprParser()
	expr, err := p.Parse(l)
	if err != nil {
		return l.Offset(), false
	}

	// a finding must not hide the next "${{ }}" of the string, only a parse error stops the check
	rule.checkExprNode(expr, line, col, checkUntrusted, workflowKey)

	return l.Offset(), true
}

func (rule *RuleExpressionInjection) exprError(err *actionlint.ExprError, lineBase, colBase int) {
	pos := convertExprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}

func (rule *RuleExpressionInjection) checkExprNode(expr actionlint.ExprNode, line, col int, checkUntrusted bool, workflowKey string) bool {
	errs := rule.checkExpressionInjection(expr)
	for _, err := range errs {
		rule.exprError(err, line, col)
	}

	return len(errs) == 0
}

func convertExprLineColToPos(line, col, lineBase, colBase int) *actionlint.Pos {
	// Line and column in ExprError are 1-based
	pos := &actionlint.Pos{Line: line - 1 + lineBase, Col: col - 1 + colBase}

	// the column of the lines of a block scalar is the negative of a column relative to the content, see posInString
	if colBase < 0 {
		pos.Col = colBase - (col - 1)
	}

	return pos
}

func (rule *RuleExpressionInjection) checkExpressionInjection(expr actionlint.ExprNode) []*actionlint.ExprError {
	errs := []*actionlint.ExprError{}

	untrusted := actionlint.NewUntrustedInputChecker(rule.untrustedRoots(evalScope{job: rule.job, step: rule.step}))
	untrusted.Init()

	inspectExprNode(expr, untrusted)

	untrusted.OnVisitEnd()
	errs = append(errs, untrusted.Errs()...)

	return errs
}

// untrustedRoots builds the untrusted input search roots for an expression evaluated in scope: the event payloads
// of actionlint, plus the values this workflow taints itself (environment variables, job outputs, step outputs and
// workflow_call inputs).
func (rule *RuleExpressionInjection) untrustedRoots(scope evalScope) actionlint.UntrustedInputSearchRoots {
	roots := actionlint.UntrustedInputSearchRoots{
		"github": actionlint.BuiltinUntrustedInputs["github"],
	}

	if children := rule.taintedEnvChildren(scope); len(children) > 0 {
		roots["env"] = actionlint.NewUntrustedInputMap("env", children...)
	}

	if children := rule.taintedNeedsChildren(); len(children) > 0 {
		roots["needs"] = actionlint.NewUntrustedInputMap("needs", children...)
	}

	if scope.job != nil {
		if children := rule.taintedStepsChildren(scope.job); len(children) > 0 {
			roots["steps"] = actionlint.NewUntrustedInputMap("steps", children...)
		}
	}

	if len(rule.callInputs) > 0 {
		children := make([]*actionlint.UntrustedInputMap, 0, len(rule.callInputs))
		for _, name := range rule.callInputs {
			children = append(children, actionlint.NewUntrustedInputMap(name))
		}
		roots["inputs"] = actionlint.NewUntrustedInputMap("inputs", children...)
	}

	return roots
}

// taintedEnvChildren returns the search nodes of the environment variables visible in scope whose value is
// tainted. The nearest definition wins: step over job over workflow.
func (rule *RuleExpressionInjection) taintedEnvChildren(scope evalScope) []*actionlint.UntrustedInputMap {
	seen := map[string]bool{}
	children := []*actionlint.UntrustedInputMap{}

	collect := func(env *actionlint.Env, defScope evalScope) {
		if env == nil {
			return
		}

		for name, v := range env.Vars {
			if seen[name] {
				continue
			}

			seen[name] = true

			if rule.envVarTainted(v, defScope) {
				children = append(children, actionlint.NewUntrustedInputMap(name))
			}
		}
	}

	if scope.step != nil {
		collect(scope.step.Env, scope)
	}

	if scope.job != nil {
		collect(scope.job.Env, evalScope{job: scope.job})
	}

	collect(rule.workflowEnv, evalScope{})

	return children
}

// taintedNeedsChildren returns the search nodes of the tainted job outputs: "needs.<job_id>.outputs.<name>".
func (rule *RuleExpressionInjection) taintedNeedsChildren() []*actionlint.UntrustedInputMap {
	children := []*actionlint.UntrustedInputMap{}

	for _, job := range rule.jobs {
		outputs := []*actionlint.UntrustedInputMap{}

		for name, o := range job.Outputs {
			if o.Name != nil {
				name = o.Name.Value
			}

			if rule.jobOutputTainted(o, job) {
				outputs = append(outputs, actionlint.NewUntrustedInputMap(name))
			}
		}

		if len(outputs) > 0 && job.ID != nil {
			children = append(children, actionlint.NewUntrustedInputMap(job.ID.Value,
				actionlint.NewUntrustedInputMap("outputs", outputs...)))
		}
	}

	return children
}

// taintedStepsChildren returns the search nodes of the tainted step outputs of the job:
// "steps.<step_id>.outputs.<name>".
func (rule *RuleExpressionInjection) taintedStepsChildren(job *actionlint.Job) []*actionlint.UntrustedInputMap {
	children := []*actionlint.UntrustedInputMap{}

	for _, s := range job.Steps {
		if s.ID == nil {
			continue
		}

		outputs := []*actionlint.UntrustedInputMap{}

		for name := range rule.githubOutputWrites(s) {
			if rule.stepOutputTainted(s, name, job) {
				outputs = append(outputs, actionlint.NewUntrustedInputMap(name))
			}
		}

		if len(outputs) > 0 {
			children = append(children, actionlint.NewUntrustedInputMap(s.ID.Value,
				actionlint.NewUntrustedInputMap("outputs", outputs...)))
		}
	}

	return children
}

func (rule *RuleExpressionInjection) envVarTainted(v *actionlint.EnvVar, scope evalScope) bool {
	if v == nil || v.Value == nil {
		return false
	}

	if t, ok := rule.taintMemo[v]; ok {
		return t
	}

	if rule.taintVisiting[v] {
		return false // a definition cycle cannot taint itself
	}

	rule.taintVisiting[v] = true
	t := rule.valueTainted(v.Value.Value, scope)
	delete(rule.taintVisiting, v)

	rule.taintMemo[v] = t

	return t
}

func (rule *RuleExpressionInjection) jobOutputTainted(o *actionlint.Output, job *actionlint.Job) bool {
	if o == nil || o.Value == nil {
		return false
	}

	if t, ok := rule.taintMemo[o]; ok {
		return t
	}

	if rule.taintVisiting[o] {
		return false
	}

	rule.taintVisiting[o] = true
	t := rule.valueTainted(o.Value.Value, evalScope{job: job})
	delete(rule.taintVisiting, o)

	rule.taintMemo[o] = t

	return t
}

func (rule *RuleExpressionInjection) stepOutputTainted(step *actionlint.Step, name string, job *actionlint.Job) bool {
	key := stepOutputKey{step, name}

	if t, ok := rule.taintMemo[key]; ok {
		return t
	}

	if rule.taintVisiting[key] {
		return false
	}

	rule.taintVisiting[key] = true

	tainted := false

	for _, v := range rule.githubOutputWrites(step)[name] {
		if rule.valueTainted(v, evalScope{job: job, step: step}) {
			tainted = true

			break
		}
	}

	delete(rule.taintVisiting, key)

	rule.taintMemo[key] = tainted

	return tainted
}

// valueTainted reports whether one of the ${{ }} expressions of the value is untrusted in scope. Boolean contexts
// (comparisons, negations) and the sanitizing functions are not tainted, like at the sinks.
func (rule *RuleExpressionInjection) valueTainted(value string, scope evalScope) bool {
	s := value

	for {
		idx := strings.Index(s, "${{")
		if idx == -1 {
			return false
		}

		s = s[idx+3:]

		l := actionlint.NewExprLexer(s)
		p := actionlint.NewExprParser()

		expr, err := p.Parse(l)
		if err != nil {
			return false
		}

		checker := actionlint.NewUntrustedInputChecker(rule.untrustedRoots(scope))
		checker.Init()

		inspectExprNode(expr, checker)

		checker.OnVisitEnd()

		if len(checker.Errs()) > 0 {
			return true
		}

		s = s[l.Offset():]
	}
}

var (
	githubOutputRe  = regexp.MustCompile(`>>\s*"?\$?(?:[Ee][Nn][Vv]:)?\{?GITHUB_OUTPUT\}?`)
	outputAssignRe  = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=`)
	outputHeredocRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)<<-?\s*'?([A-Za-z0-9_.-]+)'?`)
)

// githubOutputWrites parses the writes to GITHUB_OUTPUT of the run script of a step. It maps an output name to the
// values written to it, in the "name=value" form and in the "name<<DELIM" heredoc form.
func (rule *RuleExpressionInjection) githubOutputWrites(step *actionlint.Step) map[string][]string {
	if w, ok := rule.stepWrites[step]; ok {
		return w
	}

	writes := map[string][]string{}

	run, ok := step.Exec.(*actionlint.ExecRun)
	if !ok || run.Run == nil {
		rule.stepWrites[step] = writes

		return writes
	}

	lines := strings.Split(run.Run.Value, "\n")

	for i := 0; i < len(lines); i++ {
		loc := githubOutputRe.FindStringIndex(lines[i])
		if loc == nil {
			continue
		}

		payload := lines[i][:loc[0]]

		if m := outputHeredocRe.FindStringSubmatch(payload); m != nil {
			body := []string{}

			for i+1 < len(lines) {
				i++

				if strings.TrimSpace(lines[i]) == m[2] {
					break
				}

				body = append(body, lines[i])
			}

			writes[m[1]] = append(writes[m[1]], strings.Join(body, "\n"))

			continue
		}

		if m := outputAssignRe.FindStringSubmatchIndex(payload); m != nil {
			writes[payload[m[2]:m[3]]] = append(writes[payload[m[2]:m[3]]], payload[m[3]+1:])
		}
	}

	rule.stepWrites[step] = writes

	return writes
}

// inspectExprNode feeds the untrusted input checker with every node of expr, like actionlint does:
// the checker knows what to do with the operators (a value that is only compared is not reported, the operands of
// "||" and "&&" are, ...). That's crapy but the rule_expression.go from actionlint enforce all expression checks,
// I just want insecure checks.
func inspectExprNode(expr actionlint.ExprNode, untrusted *actionlint.UntrustedInputChecker) {
	skipped := 0 // depth in the operands of an operator that returns a boolean

	actionlint.VisitExprNode(expr, func(n, _ actionlint.ExprNode, entering bool) {
		switch n.(type) {
		case *actionlint.CompareOpNode, *actionlint.NotOpNode:
			// "title == 'x'" is a boolean: it can't carry an injection even if the operand is untrusted
			if entering {
				skipped++

				return
			}

			skipped--
		default:
			if skipped > 0 {
				return
			}
		}

		if entering {
			untrusted.OnVisitNodeEnter(n)
		} else {
			untrusted.OnVisitNodeLeave(n)
		}
	})
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children
func (rule *RuleExpressionInjection) VisitWorkflowPost(n *actionlint.Workflow) error {

	if !rule.skip {
		cleanLogMessages(rule.Errs())
	}

	return nil
}

func cleanLogMessages(errs []*actionlint.Error) {
	for _, e := range errs {
		msg := strings.Split(e.Message, ". ")
		e.Message = "Expression injection, " + msg[0] + "."
	}
}

func (rule *RuleExpressionInjection) checkContainer(c *actionlint.Container, workflowKey, childWorkflowKeyPrefix string) {
	if c == nil {
		return
	}
	childWorkflowKey := workflowKey
	if childWorkflowKeyPrefix != "" {
		childWorkflowKey += "." + childWorkflowKeyPrefix
	}
	rule.checkString(c.Image, workflowKey)
	//rule.checkEnv(c.Env, workflowKey+".env.<env_id>") // e.g. jobs.<job_id>.container.env.<env_id>
	rule.checkString(c.Options, workflowKey)
}
