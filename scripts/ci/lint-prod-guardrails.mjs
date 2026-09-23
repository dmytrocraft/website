#!/usr/bin/env node
// Production-safety guardrail gate (issues #383, #375 and #380).
//
// Seven invariants only ever hold in production, where no PR check watches
// them, so each has already regressed silently at least once in this class of
// repo. This gate is hermetic (it reads committed files, never the network) and
// therefore runs inside `make lint` on every PR:
//
//   A. Every privileged workflow (assumes an AWS role, or cuts a release) that
//      runs on a non-pull-request trigger must be covered by an alert/audit
//      workflow, so a post-merge failure reaches a human.
//   B. The CloudFront edge handler must keep its allow-list + synthetic 404 and
//      must stay pinned inside the 100%-coverage `edge` Jest layer, so it can
//      never silently degrade into an unconditional origin pass-through.
//   C. `next.config.js` must not enable productionBrowserSourceMaps, which
//      publishes readable application source to the CDN.
//   D. Every CloudFront Function source must fit the service's 10 KB function
//      quota, which is not adjustable. The infra repository publishes these files
//      verbatim from `main`, so an oversized one is rejected at apply time and
//      the distribution keeps running whatever version it had — which is how the
//      `/en` rewrite shipped in git and 404'd in production (docs/edge-routing.md).
//   E. Every job that assumes an AWS role in a workflow reachable from any
//      trigger other than `pull_request` must declare a GitHub `environment:`
//      (a string, or a mapping with `name`), so the environment's protection
//      rules -- required reviewers, wait timer, deployment branches -- stand in
//      front of the role. `pull_request` alone is exempt, and only because of
//      the OIDC-subject trap: naming an environment changes the subject GitHub
//      mints from `repo:<org>/<repo>:pull_request` to
//      `repo:<org>/<repo>:environment:<name>`, and the deployed sandbox role
//      trust policies reject that subject, so the key fails
//      sts:AssumeRoleWithWebIdentity on every run (.github/sandbox_workflows.md
//      records the failed run). Widening those trust policies is the
//      prerequisite for lifting the exemption. pull_request_target, merge_group,
//      push, schedule, workflow_dispatch, workflow_run and every other trigger
//      are never exempt. A role is assumed through
//      aws-actions/configure-aws-credentials, any `with: role-to-assume` input,
//      or `aws sts assume-role` in a run body; the steps of a local composite
//      action are followed, because moving the login into one must not move it
//      out of the audit, and a local action this gate cannot read fails closed.
//   F. A `run:` step that appends a variable named like a credential
//      (TOKEN, SECRET, PASSWORD, PRIVATE_KEY, CREDENTIAL) to $GITHUB_ENV or
//      $GITHUB_OUTPUT must have printed `::add-mask::` for THAT value earlier
//      in the SAME step, so it is redacted from the job log before it is
//      persisted into every later step. A mask of some other value vouches
//      for nothing. The write is read off the parsed `run:` string line by
//      line -- `>> "$GITHUB_ENV"`, `>>$GITHUB_ENV`, `tee -a`, printf with its
//      `%s` resolved to the argument it prints, a grouped `{ ...; } >>` block,
//      the `NAME<<EOF` multi-line form, a heredoc redirected into the file,
//      PowerShell's Out-File / Add-Content and cmd's `>>%GITHUB_ENV%` -- and a
//      write whose variable or value the gate cannot read is reported too:
//      fail closed rather than guess. A line that only reads the file
//      (`test -w "$GITHUB_ENV"`) is not a write.
//   G. The sandbox lifecycle is symmetric and opt-in. The workflow that starts
//      the `sandbox-creation` CodePipeline must run only on the
//      `pull_request` `labeled` type, so a billed execution needs an explicit
//      PR label; the workflow that starts
//      `sandbox-deletion` must run on `pull_request` with `closed` as its only
//      type and on nothing else. Every provisioned
//      environment is billed until the deletion pipeline reclaims it, and
//      that pipeline is only ever reached through a pull request closing --
//      so a sandbox created from a bare branch push, a manual dispatch or a
//      schedule has no matching teardown event and is orphaned at AWS cost
//      (issue #380 F2, the `push: branches-ignore: [main]` trigger that
//      #375 removed). The two workflows are found by the pipeline each one
//      starts, not by filename, and the assertion fails closed when neither
//      half is found rather than passing over a lifecycle it cannot see.
//
// Collect-all-then-fail: every violation is reported in one run.
import fs from 'node:fs';
import path from 'node:path';

import yaml from 'js-yaml';

const WORKFLOW_DIR = '.github/workflows';
const ACTIONS_DIR = '.github/actions';
const EDGE_SCRIPT = 'scripts/cloudfront_routing.js';
const HEADERS_SCRIPT = 'scripts/cloudfront_security_headers.js';
const JEST_CONFIG = 'jest.config.ts';

// AWS documents the quota as "10 KB" without saying which kilobyte it means, so
// the stricter reading is the one enforced: 10,000 bytes of UTF-8 source, which is
// what the API receives. Comments count — the file is uploaded as written.
const CLOUDFRONT_FUNCTION_MAX_BYTES = 10_000;
const CLOUDFRONT_FUNCTIONS = [EDGE_SCRIPT, HEADERS_SCRIPT];
const NEXT_CONFIG = 'next.config.js';

// A privileged workflow whose triggers are all PR-scoped is already watched: a
// failure lands as a red check on the pull request. Every other trigger runs
// where nobody is looking.
const WATCHED_TRIGGERS = new Set(['pull_request', 'pull_request_target', 'merge_group']);

// Assertion E exempts strictly less than assertion A does. `pull_request_target`
// and `merge_group` runs are watched (their failure is a red check), but they
// mint OIDC subjects the sandbox trust policies were never proved against, so
// nothing about the sandbox trap excuses them from an environment gate.
const ENVIRONMENT_EXEMPT_TRIGGER = 'pull_request';

const AWS_CREDENTIALS_ACTION = 'aws-actions/configure-aws-credentials';
// The action is the documented path, but a role can also be assumed straight
// from the CLI.
const AWS_CLI_ASSUME_ROLE = /\baws\s+sts\s+assume-role(?:-with-web-identity)?\b/;
const LOCAL_ACTION_USES = /^\.\//;

// Assertion F. The name test is deliberately a substring match, so `GH_TOKEN`,
// `NPM_TOKEN`, `DB_PASSWORD` and `AWS_SECRET_ACCESS_KEY` all count.
const CREDENTIAL_NAME = /TOKEN|SECRET|PASSWORD|PRIVATE_KEY|CREDENTIAL/i;
// A write into one of the two files GitHub reads back, in any spelling of
// the file (`$GITHUB_ENV`, `"${GITHUB_ENV}"`, PowerShell's `$env:GITHUB_ENV`,
// cmd's `%GITHUB_ENV%`) and any write operator: `>>`, `>`, `tee [-a]`,
// PowerShell's `Out-File`/`Add-Content` with their switches. A line that
// merely reads the file (`test -w "$GITHUB_ENV"`, `cat "$GITHUB_OUTPUT"`)
// persists nothing and is not a write.
const PERSISTED_WRITE =
  /(?:>>?|\btee\b(?:\s+-\w+)*|\b(?:Out-File|Add-Content)\b(?:\s+-\w+(?:\s+[^\s-]\S*)?)*)\s*["']?(?:\$\{?(?:env:)?|%)(GITHUB_(?:ENV|OUTPUT))\b/;
const ADD_MASK = '::add-mask::';
// The value half of a `NAME=value` write: a command substitution, a braced or
// bare variable, a printf placeholder that the format arguments fill, or a
// literal. Anything else is unreadable and fails closed.
const VALUE_HEAD = /^(?:\$\(|\$\{|\$[A-Za-z_]|%[sbq]|[^\s"'|;&>]+)/;
// A `NAME=` or `NAME<<` token that is not itself a variable expansion
// (`$name=`), so `echo "TOKEN=$x"`, `printf 'TOKEN=%s'`, `echo TOKEN=$x` and
// `echo 'TOKEN<<EOF'` all yield TOKEN.
const WRITTEN_NAME = /(?<![\w$])([A-Za-z_][\w-]*)(=|<<)/g;
// A shell heredoc redirection (`cat <<EOF`, `tee -a "$GITHUB_ENV" <<'EOF'`),
// as distinct from the `NAME<<EOF` value form, where `<<` abuts the name, and
// from a `<<<` here-string.
const HEREDOC_OPENER = /(?<![\w<])<<(?!<)-?\s*(['"]?)([A-Za-z_]\w*)\1/;
// Assertion G. The lifecycle is keyed on the pipeline a step starts; the
// `--name` may sit on a continuation line after `\` or be spelled `--name=`,
// so the match spans lines and both spellings.
const SANDBOX_PIPELINE_START = /\baws\s+codepipeline\s+start-pipeline-execution\b/;
const SANDBOX_CREATION_PIPELINE = 'sandbox-creation';
const SANDBOX_DELETION_PIPELINE = 'sandbox-deletion';
const SANDBOX_CREATION_TRIGGER = 'pull_request';
const SANDBOX_CREATION_TYPE = 'labeled';
const SANDBOX_TEARDOWN_TYPE = 'closed';
const RELEASE_ACTIONS = [
  'actions/create-release',
  'softprops/action-gh-release',
  'ncipollo/release-action',
  'TriPSs/conventional-changelog-action',
];

const root = path.resolve(process.argv[2] ?? process.cwd());
const failures = [];

function fail(assertion, message) {
  failures.push(`[${assertion}] ${message}`);
}

function readIfPresent(relative) {
  const full = path.join(root, relative);
  return fs.existsSync(full) ? fs.readFileSync(full, 'utf8') : null;
}

function loadWorkflows() {
  const dir = path.join(root, WORKFLOW_DIR);
  if (!fs.existsSync(dir)) {
    fail('A', `${WORKFLOW_DIR}/ is missing; the privileged-workflow audit cannot run.`);
    return [];
  }
  return fs
    .readdirSync(dir)
    .filter(file => /\.ya?ml$/.test(file))
    .map(file => {
      let doc;
      try {
        doc = yaml.load(fs.readFileSync(path.join(dir, file), 'utf8')) ?? {};
      } catch (error) {
        // An unparseable workflow must be a reported failure, not a stack trace:
        // a duplicate key or bad indent would otherwise crash the gate and take
        // assertions B and C down with it, hiding unrelated regressions.
        fail(
          'A',
          `${WORKFLOW_DIR}/${file} is not valid YAML, so its privileges cannot be audited: ` +
            `${error.message.split('\n')[0]}`
        );
        return null;
      }
      // YAML 1.1 folds a bare `on:` key to boolean true; js-yaml v4 (YAML 1.2
      // core) keeps it a string. Read both so the gate is parser-agnostic.
      // (A boolean key reaches JS as the string 'true', hence `doc.true`.)
      const triggers = doc.on ?? doc.true ?? {};
      return { file, name: typeof doc.name === 'string' ? doc.name : file, doc, triggers };
    })
    .filter(Boolean);
}

// The local composite actions, keyed by the `uses:` spelling that reaches
// them (`./.github/actions/<name>`). Assertion E follows their steps and
// assertion F audits their run bodies, so a login or a persisted credential
// moved into a composite stays inside the gate.
function loadLocalActions() {
  const dir = path.join(root, ACTIONS_DIR);
  const actions = new Map();
  if (!fs.existsSync(dir)) return actions;
  fs.readdirSync(dir, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .forEach(entry => {
      const relativeDir = `${ACTIONS_DIR}/${entry.name}`;
      const file = ['action.yml', 'action.yaml']
        .map(name => `${relativeDir}/${name}`)
        .find(relative => fs.existsSync(path.join(root, relative)));
      // A directory with no action metadata is not an action; a `uses:` that
      // points at it stays unresolved and fails closed in assertion E.
      if (!file) return;
      let doc;
      try {
        doc = yaml.load(fs.readFileSync(path.join(root, file), 'utf8')) ?? {};
      } catch (error) {
        fail(
          'E',
          `${file} is not valid YAML, so the jobs that call it cannot be audited: ` +
            `${error.message.split('\n')[0]}`
        );
        return;
      }
      const steps = Array.isArray(doc?.runs?.steps) ? doc.runs.steps : [];
      actions.set(`./${relativeDir}`, { file, steps });
    });
  return actions;
}

function jobsOf(doc) {
  return doc?.jobs && typeof doc.jobs === 'object' ? Object.entries(doc.jobs) : [];
}

function stepsOfJob(job) {
  return Array.isArray(job?.steps) ? job.steps : [];
}

function stepsOf(doc) {
  return jobsOf(doc).flatMap(([, job]) => stepsOfJob(job));
}

function usesOf(step) {
  return typeof step?.uses === 'string' ? step.uses : '';
}

function runOf(step) {
  return typeof step?.run === 'string' ? step.run : '';
}

// The three spellings through which a step itself takes on an AWS role.
function assumesAwsRoleDirectly(step) {
  const hasRoleInput =
    step?.with && typeof step.with === 'object' && Object.hasOwn(step.with, 'role-to-assume');
  return (
    usesOf(step).startsWith(AWS_CREDENTIALS_ACTION) ||
    Boolean(hasRoleInput) ||
    AWS_CLI_ASSUME_ROLE.test(runOf(step))
  );
}

// Assertion A's predicate. A local composite action hides its steps from the
// alert audit, so the caller is treated as privileged rather than as invisible
// -- which is why every non-PR caller of the dev-container composite is listed
// in ci-health-alerts.yml.
function assumesAwsRole(step) {
  return assumesAwsRoleDirectly(step) || /^\.\/\.github\/actions\//.test(usesOf(step));
}

// Assertion D's step set: the job's own steps plus those of every local action
// it calls, followed transitively. A local `uses:` with no readable action
// metadata is returned separately so the caller can fail closed on it instead
// of treating the unreadable action as one that assumes nothing.
function resolveSteps(steps, localActions, seen = new Set()) {
  const resolved = [];
  const unresolved = [];
  steps.forEach(step => {
    resolved.push(step);
    const uses = usesOf(step);
    if (!LOCAL_ACTION_USES.test(uses)) return;
    const action = localActions.get(uses.replace(/\/+$/, ''));
    if (!action) {
      unresolved.push(uses);
      return;
    }
    if (seen.has(action.file)) return;
    seen.add(action.file);
    const nested = resolveSteps(action.steps, localActions, seen);
    resolved.push(...nested.resolved);
    unresolved.push(...nested.unresolved);
  });
  return { resolved, unresolved };
}

function createsRelease(step) {
  const uses = usesOf(step);
  return (
    RELEASE_ACTIONS.some(action => uses.startsWith(action)) ||
    /\bgh\s+release\s+create\b/.test(runOf(step))
  );
}

function triggerKeys(triggers) {
  if (Array.isArray(triggers)) return triggers.map(String);
  if (typeof triggers === 'string') return [triggers];
  return triggers && typeof triggers === 'object' ? Object.keys(triggers) : [];
}

function runsUnwatched(triggers) {
  return triggerKeys(triggers).some(key => !WATCHED_TRIGGERS.has(key));
}

// A workflow only provides coverage if it can actually reach a human, i.e. it
// grants `issues: write` (files/refreshes the ci-alert or ledger issue). Without
// that test, adding any unrelated `workflow_run` listener — or a release
// workflow that listens to its own `release` event — would satisfy the audit
// requirement while alerting nobody.
function canAlertHumans(doc) {
  const jobs = doc?.jobs && typeof doc.jobs === 'object' ? Object.values(doc.jobs) : [];
  const grantsIssueWrite = perms => perms && typeof perms === 'object' && perms.issues === 'write';
  return grantsIssueWrite(doc?.permissions) || jobs.some(job => grantsIssueWrite(job?.permissions));
}

// Coverage is a relationship across the workflow directory rather than a
// hardcoded filename, so renaming the alert workflow does not silently disable
// this assertion — but only alerting workflows count, and a workflow can never
// vouch for itself.
function collectAlertCoverage(workflows, audited) {
  const alertedNames = new Set();
  let hasReleaseAudit = false;
  workflows.forEach(workflow => {
    if (workflow.file === audited.file) return;
    if (!canAlertHumans(workflow.doc)) return;
    const listed = workflow.triggers?.workflow_run?.workflows;
    if (Array.isArray(listed)) listed.forEach(name => alertedNames.add(String(name)));
    if (triggerKeys(workflow.triggers).includes('release')) hasReleaseAudit = true;
  });
  return { alertedNames, hasReleaseAudit };
}

function assertPrivilegedWorkflowsAreAlerted(workflows) {
  workflows.forEach(workflow => {
    const steps = stepsOf(workflow.doc);
    const aws = steps.some(assumesAwsRole);
    const release = steps.some(createsRelease);
    if (!aws && !release) return;
    if (!runsUnwatched(workflow.triggers)) return;
    const { alertedNames, hasReleaseAudit } = collectAlertCoverage(workflows, workflow);
    if (alertedNames.has(workflow.name)) return;
    if (release && !aws && hasReleaseAudit) return;
    const privilege = aws ? 'assumes an AWS role' : 'creates a GitHub release';
    fail(
      'A',
      `${WORKFLOW_DIR}/${workflow.file} (name: "${workflow.name}") ${privilege} on a ` +
        `non-pull-request trigger, but no workflow lists "${workflow.name}" under ` +
        `on.workflow_run.workflows. Add it to the alert workflow ` +
        `(${WORKFLOW_DIR}/ci-health-alerts.yml) so a post-merge failure reaches a human.`
    );
  });
}

// `environment: production` and `environment: { name: production, url: ... }`
// both name an environment; an empty string, a bare `url`, or a list do not,
// and a key that survives only in a comment never reaches the parser at all.
function declaresEnvironment(job) {
  const environment = job?.environment;
  if (typeof environment === 'string') return environment.trim().length > 0;
  if (environment && typeof environment === 'object' && !Array.isArray(environment)) {
    return typeof environment.name === 'string' && environment.name.trim().length > 0;
  }
  return false;
}

function assertRoleAssumingJobsDeclareEnvironment(workflows, localActions) {
  workflows.forEach(workflow => {
    const unexempt = triggerKeys(workflow.triggers).filter(
      key => key !== ENVIRONMENT_EXEMPT_TRIGGER
    );
    if (unexempt.length === 0) return;
    const location = `${WORKFLOW_DIR}/${workflow.file}`;
    jobsOf(workflow.doc).forEach(([jobId, job]) => {
      const { resolved, unresolved } = resolveSteps(stepsOfJob(job), localActions);
      unresolved.forEach(uses => {
        fail(
          'E',
          `${location} job "${jobId}" runs on ${unexempt.join(', ')} and calls the local ` +
            `action ${uses}, which has no readable action.yml under ${ACTIONS_DIR}/, so this ` +
            'gate cannot prove the job assumes no AWS role. Place the action under ' +
            `${ACTIONS_DIR}/<name>/action.yml.`
        );
      });
      if (!resolved.some(assumesAwsRoleDirectly)) return;
      if (declaresEnvironment(job)) return;
      fail(
        'E',
        `${location} job "${jobId}" assumes an AWS role and is reachable from ` +
          `${unexempt.join(', ')}, but declares no environment:. Name a GitHub environment ` +
          '(a string, or a mapping with name) so its protection rules stand in front of the ' +
          'role -- and widen the role trust policy to the ' +
          'repo:<org>/<repo>:environment:<name> subject FIRST (.github/sandbox_workflows.md), ' +
          'or the key fails sts:AssumeRoleWithWebIdentity on every run.'
      );
    });
  });
}

// Assertion E helpers. Everything below reads the parsed `run:` string of one
// step, never the workflow file, so a `#` here is a shell comment: a whole
// comment line is inert in every shell GitHub runs and is skipped on both
// sides, while a trailing comment is only honoured for the mask -- not
// counting a mask that a comment swallowed is the fail-closed direction, and
// counting a name a trailing comment mentions merely over-reports.
function isShellComment(line) {
  return /^\s*#/.test(line);
}

// A balanced `$( ... )` starting at `at`, or null when it never closes.
function commandSubstitutionAt(text, at) {
  let depth = 0;
  for (let index = at + 1; index < text.length; index += 1) {
    if (text[index] === '(') depth += 1;
    if (text[index] === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(at, index + 1);
    }
  }
  return null;
}

// One value expression in the form the mask and the write are compared in:
// `$VAR`, `${VAR}`, `"$VAR"`, `$env:VAR` and cmd's `%VAR%` all become VAR;
// `$(cmd)` keeps its command text with whitespace collapsed; a literal is kept
// verbatim. Two expressions that normalise to the same string name the same
// value.
function normaliseValue(raw) {
  const text = raw.trim().replace(/^(["'])(.*)\1$/, '$2');
  if (text.startsWith('$(')) {
    const inner = commandSubstitutionAt(text, 0);
    return inner === null ? text : `$(${inner.slice(2, -1).replace(/\s+/g, ' ').trim()})`;
  }
  const variable = /^(?:\$\{?(?:env:)?([A-Za-z_]\w*)\}?|%([A-Za-z_]\w*)%)$/.exec(text);
  return variable ? (variable[1] ?? variable[2]) : text;
}

// The value token that starts at `at` in `text`: the whole `$( ... )`, the
// `${...}`, the `$NAME`, the printf placeholder, or the literal up to the next
// shell delimiter. Null when nothing readable starts there.
function valueTokenAt(text, at) {
  const rest = text.slice(at);
  if (rest.startsWith('$(')) return commandSubstitutionAt(text, at);
  if (rest.startsWith('${')) {
    const close = rest.indexOf('}');
    return close < 0 ? null : rest.slice(0, close + 1);
  }
  const cmdVariable = /^%[A-Za-z_]\w*%/.exec(rest);
  if (cmdVariable) return cmdVariable[0];
  const head = VALUE_HEAD.exec(rest);
  if (!head) return null;
  if (head[0].startsWith('$')) return /^\$(?:env:)?[A-Za-z_]\w*/.exec(rest)[0];
  return head[0];
}

// The format arguments of a printf on `line`, in order, so `%s` placeholders
// in a `NAME=%s` format resolve to the values they print.
function printfArguments(line) {
  const match = /\bprintf\s+(?:--\s+)?(?:"(?:[^"\\]|\\.)*"|'[^']*'|\S+)\s*([^|>;]*)/.exec(line);
  if (!match) return [];
  return match[1].trim().split(/\s+/).filter(Boolean).map(normaliseValue);
}

// Every masked expression a live `::add-mask::` on `line` prints before column
// `before` (the whole line when omitted), normalised. A marker behind a `#`
// never reaches stdout and so masks nothing.
function maskedValuesOn(line, before = line.length) {
  const comment = line.search(/(?:^|\s)#/);
  const values = [];
  let at = line.indexOf(ADD_MASK);
  while (at >= 0 && at < before && !(comment >= 0 && comment < at)) {
    const after = at + ADD_MASK.length;
    const quote = at > 0 && /["']/.test(line[at - 1]) ? line[at - 1] : null;
    const end = quote ? line.indexOf(quote, after) : line.slice(after).search(/[\s;|&]|$/) + after;
    values.push(normaliseValue(line.slice(after, end < 0 ? line.length : end)));
    at = line.indexOf(ADD_MASK, after);
  }
  return values;
}

// The `{ name, values }` pairs a stretch of text persists through `NAME=value`
// tokens: the value expression for `=`, and -- for the `NAME<<EOF` form -- the
// producer lines between the name and its terminator, each treated as a
// command whose output is the value. A value the gate cannot read is recorded
// as null, which the caller reports rather than guesses about.
function assignmentsIn(lines, printfValues = []) {
  const assignments = [];
  lines.forEach((line, index) => {
    for (const match of line.matchAll(WRITTEN_NAME)) {
      const name = match[1];
      if (match[2] === '<<') {
        const terminator = /^['"]?([A-Za-z_]\w*)/.exec(
          line.slice(match.index + match[0].length)
        )?.[1];
        const body = [];
        for (let next = index + 1; next < lines.length; next += 1) {
          if (lines[next].trim().replace(/^echo\s+['"]?|['"]$/g, '') === terminator) break;
          body.push(lines[next].trim());
        }
        assignments.push({ name, values: body.map(producer => normaliseValue(`$(${producer})`)) });
        continue;
      }
      const token = valueTokenAt(line, match.index + match[0].length);
      let values = null;
      if (token !== null && /^%[sbq]$/.test(token)) {
        values = printfValues.length ? [printfValues.shift()] : null;
      } else if (token !== null) {
        values = [normaliseValue(token)];
      }
      assignments.push({ name, values });
    }
  });
  return assignments;
}

// The lines of a `{ ...; } >> "$GITHUB_ENV"` / `( ... ) >> ...` group whose
// closing bracket is on `closeIndex`, walked backwards to the bracket that
// opened it. Brackets are counted rather than parsed, so a group that never
// balances hands back everything above it -- a superset, which can only
// over-report.
function groupLines(lines, closeIndex) {
  const body = [];
  let depth = 0;
  for (let index = closeIndex; index >= 0; index -= 1) {
    const line = lines[index];
    depth += (line.match(/[})]/g) ?? []).length - (line.match(/[{(]/g) ?? []).length;
    if (index < closeIndex) body.unshift(line);
    if (depth <= 0) break;
  }
  return body;
}

// The body of the heredoc opened on `openIndex`: every following line up to
// the terminator, or to the end of the step when no terminator is found.
function heredocLines(lines, openIndex, terminator) {
  const body = [];
  for (let index = openIndex + 1; index < lines.length; index += 1) {
    if (lines[index].replace(/^\t+/, '') === terminator) break;
    body.push(lines[index]);
  }
  return body;
}

// What the write on `index` persists: the `{ name, values }` assignments read
// from the line itself, from the group it closes and from the heredoc it
// opens, plus -- when no assignment can be read at all -- the command whose
// output is being appended (`cat generated.env >> "$GITHUB_ENV"`), so a mask
// of exactly that output (`::add-mask::$(cat generated.env)`) can still vouch
// for it. An empty result means the gate could not read the write.
function persistedAt(lines, index) {
  const line = lines[index];
  const heredoc = HEREDOC_OPENER.exec(line);
  const scope = [line];
  if (/^\s*[})]/.test(line)) scope.unshift(...groupLines(lines, index));
  if (heredoc) scope.push(...heredocLines(lines, index, heredoc[2]));
  const assignments = assignmentsIn(scope, printfArguments(line));
  if (assignments.length > 0) return assignments;
  const producer = line
    .slice(0, PERSISTED_WRITE.exec(line).index)
    .replace(/\s*[|>]+\s*$/, '')
    .trim();
  return producer && !heredoc && !/^[})]/.test(producer)
    ? [{ name: null, values: [normaliseValue(`$(${producer})`)] }]
    : [];
}

function describeWrite(index, file, line) {
  return `line ${index + 1} writes to $${file} (\`${line.trim()}\`)`;
}

// The findings for one step's run body, in source order. `masked` holds every
// value expression an earlier live `::add-mask::` printed; a credential is
// covered only when the value it persists is one of them, so masking an
// unrelated value earlier in the step vouches for nothing.
function auditRunBody(run) {
  const lines = run.split(/\r?\n/);
  const findings = [];
  const masked = new Set();
  lines.forEach((line, index) => {
    if (isShellComment(line)) return;
    const write = PERSISTED_WRITE.exec(line);
    if (write) {
      const file = write[1];
      // A mask printed later on the same line lands after the write, so only
      // the ones before it count for this line.
      maskedValuesOn(line, write.index).forEach(value => masked.add(value));
      const persisted = persistedAt(lines, index);
      const credentials = persisted.filter(
        entry => entry.name === null || CREDENTIAL_NAME.test(entry.name)
      );
      const unreadable = persisted.length === 0 || credentials.some(entry => entry.values === null);
      const uncovered = credentials
        .filter(entry => entry.values !== null)
        .flatMap(entry =>
          entry.values.filter(value => !masked.has(value)).map(value => ({ entry, value }))
        );
      if (unreadable || uncovered.every(({ entry }) => entry.name === null)) {
        if (unreadable || uncovered.length > 0) {
          const outputs = uncovered.map(({ value }) => value);
          findings.push(
            `${describeWrite(index, file, line)} but the gate cannot tell ` +
              `which variable it persists; print ${ADD_MASK} on exactly what is appended` +
              `${outputs.length ? ` (${outputs.join(', ')})` : ''} first, or spell the write as ` +
              `echo "NAME=$VALUE" >> "$${file}" so the name and the value can be read.`
          );
        }
      } else if (uncovered.length > 0) {
        const names = [...new Set(uncovered.map(({ entry }) => entry.name ?? 'its output'))];
        const values = [...new Set(uncovered.map(({ value }) => value))];
        findings.push(
          `line ${index + 1} writes ${names.join(', ')} to $${file} without printing ` +
            `${ADD_MASK} for ${values.join(', ')} earlier in the same step; mask the value ` +
            `that is persisted (echo "${ADD_MASK}$VALUE") before it is persisted, or do not ` +
            'persist it. A mask of some other value does not cover it.'
        );
      }
    }
    maskedValuesOn(line).forEach(value => masked.add(value));
  });
  return findings;
}

function assertCredentialsMaskedBeforePersisting(workflows, localActions) {
  const sources = [
    ...workflows.map(workflow => ({
      file: `${WORKFLOW_DIR}/${workflow.file}`,
      jobs: jobsOf(workflow.doc),
    })),
    ...[...localActions.values()].map(action => ({
      file: action.file,
      jobs: [['runs', { steps: action.steps }]],
    })),
  ];
  sources.forEach(({ file, jobs }) => {
    jobs.forEach(([jobId, job]) => {
      stepsOfJob(job).forEach((step, index) => {
        if (typeof step?.run !== 'string') return;
        const label = typeof step.name === 'string' ? ` ("${step.name}")` : '';
        auditRunBody(step.run).forEach(finding => {
          fail('F', `${file} job "${jobId}" step ${index + 1}${label}: ${finding}`);
        });
      });
    });
  });
}

// The behavioural contract (which URIs 404) is owned by the 100%-coverage edge
// Jest layer, which vm-loads this exact file. What that layer structurally
// cannot assert about itself is the shape below: that the allow-list maps are
// still immutable and that the handler still fails closed instead of ending in
// an unconditional origin pass-through.
// The semicolon is optional (ASI makes a bare `return request` valid) and a
// trailing comment must not hide the fallthrough, so comments are stripped
// before this is applied rather than being tolerated by the pattern.
const ORIGIN_PASSTHROUGH_TAIL = /return\s+request(?:\.uri)?\s*;?$/;

// The handler dereferences all four tables, so every one of them is load-bearing.
const REQUIRED_EDGE_TABLES = ['ROUTE_MAP', 'ALLOWED_DIRS', 'ALLOWED_FILES', 'ALLOWED_EXTENSIONS'];

// Line and block comments only — enough to normalise a tail like
// `return request; // TODO` without pulling in a JS parser for one assertion.
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
}

function assertEdgeAllowListIntact() {
  const source = readIfPresent(EDGE_SCRIPT);
  if (source === null) {
    fail('B', `${EDGE_SCRIPT} is missing; the production edge routing contract is unenforceable.`);
    return;
  }

  // Every structural check below runs on a comment-stripped copy. A comment can
  // otherwise both hide a violation (`map/* x */: true`) and break an extraction
  // (a `})` inside a comment ends the table capture early), and a commented-out
  // declaration must not count as a live one.
  const code = stripComments(source);

  // `var|let|const`: the file is ES5.1 today, but a later edit to `const` must not
  // silently drop the ALLOWED_* tables out of this audit and take the
  // immutability check with them.
  const maps = [
    ...code.matchAll(/(?:var|let|const)\s+(ROUTE_MAP|ALLOW(?:ED)?_[A-Z0-9_]+)\s*=\s*(\S+)/g),
  ];
  // Deleting a table is as dangerous as unfreezing one: the file is `'use strict'`,
  // so the reads left behind in the handler throw a ReferenceError inside the try
  // and the catch turns that into the unconditional origin pass-through this
  // assertion exists to prevent. Checking only ROUTE_MAP left three tables open.
  REQUIRED_EDGE_TABLES.forEach(table => {
    if (maps.some(([, name]) => name === table)) return;
    fail(
      'B',
      `${EDGE_SCRIPT} no longer declares the ${table} allow-list, but the handler still ` +
        'reads it. The missing binding throws and the catch falls through to the origin.'
    );
  });
  maps
    .filter(([, , initialiser]) => !initialiser.startsWith('Object.freeze('))
    .forEach(([, name]) => {
      fail('B', `${EDGE_SCRIPT}: ${name} is not Object.freeze()d; the allow-list is mutable.`);
    });

  if (!/statusCode:\s*404/.test(code)) {
    fail('B', `${EDGE_SCRIPT} no longer builds a synthetic 404 response for unknown paths.`);
  }

  // `map` in the extension table would publish browser source maps through the
  // edge even while next.config.js keeps them off — the routing policy forbids it
  // outright, so it is asserted here rather than left to review.
  const extensionTable = /ALLOWED_EXTENSIONS\s*=\s*Object\.freeze\(\{([\s\S]*?)\}\)/.exec(code);
  if (extensionTable && /(^|[\s{,'"])map\s*:/.test(extensionTable[1])) {
    fail(
      'B',
      `${EDGE_SCRIPT}: 'map' is in ALLOWED_EXTENSIONS; that publishes browser source maps ` +
        'through the edge. It must never be added.'
    );
  }

  const tryBlock = /try\s*\{([\s\S]*?)\}\s*catch\s*\(/.exec(code)?.[1];
  if (tryBlock === undefined) {
    fail('B', `${EDGE_SCRIPT}: could not locate the handler try/catch block to audit its exit.`);
    return;
  }
  if (ORIGIN_PASSTHROUGH_TAIL.test(tryBlock.trimEnd())) {
    fail(
      'B',
      `${EDGE_SCRIPT}: the handler's try block ends in an unconditional \`return request\`, so a ` +
        'non-allow-listed path falls through to the origin. It must fail closed by returning ' +
        'the synthetic 404 response.'
    );
  }
}

function assertEdgeCoverageStaysPinned() {
  const config = readIfPresent(JEST_CONFIG);
  if (config === null) {
    fail('B', `${JEST_CONFIG} is missing; the edge coverage pin cannot be verified.`);
    return;
  }
  // Same comment-stripped copy as the allow-list audit, for the same reason: a
  // commented-out entry or threshold must not count as a live one, and a `;`
  // inside a comment would truncate either capture below.
  const code = stripComments(config);
  const collectFrom = /const EDGE_COVERAGE_FROM[^;]*;/.exec(code)?.[0] ?? '';
  // Compare against the extracted quoted elements rather than building a regex out
  // of a path: hand-escaping only `.` leaves every other metacharacter (a backslash
  // above all) unescaped, which is the incomplete-escaping defect CodeQL flags. The
  // pin is matched against exactly the two spellings Jest resolves to the repo file --
  // the bare path and the `<rootDir>/`-prefixed one -- because anything looser passes
  // an entry that never collects this file: one merely ending in the same tail
  // (`<rootDir>/../../other/scripts/cloudfront_routing.js`), a negated glob that tells
  // Jest to exclude it (`!<rootDir>/scripts/cloudfront_routing.js`), or a longer
  // sibling (`...cloudfront_routing.js.map`).
  const collectedEntries = [...collectFrom.matchAll(/(['"])([^'"]*)\1/g)].map(match => match[2]);
  const pinsEdgeScript = collectedEntries.some(
    entry => entry === EDGE_SCRIPT || entry === `<rootDir>/${EDGE_SCRIPT}`
  );
  if (!pinsEdgeScript) {
    fail(
      'B',
      `${JEST_CONFIG} no longer collects edge coverage from ${EDGE_SCRIPT}; ` +
        'the 100% edge layer would stop guarding the routing allow-list.'
    );
  }
  const threshold = /const EDGE_COVERAGE_THRESHOLD[^;]*;/.exec(code)?.[0] ?? '';
  ['branches', 'functions', 'lines', 'statements'].forEach(counter => {
    if (!new RegExp(`${counter}:\\s*100\\b`).test(threshold)) {
      fail('B', `${JEST_CONFIG} no longer pins the edge coverage threshold ${counter} at 100.`);
    }
  });
}

function assertNoProductionSourceMaps() {
  const config = readIfPresent(NEXT_CONFIG);
  if (config === null) {
    fail('C', `${NEXT_CONFIG} is missing; the source-map guardrail cannot be verified.`);
    return;
  }
  // Comments are stripped so prose mentioning the option cannot trip the gate.
  const code = stripComments(config);
  // Three spellings reach the same setting and all must be caught: an object
  // literal property (`productionBrowserSourceMaps: true`), an assignment
  // (`config.productionBrowserSourceMaps = true`), and a quoted/computed key
  // (`['productionBrowserSourceMaps']: true`). Anything other than a literal
  // `false` is rejected — including a variable, whose value this gate cannot
  // know, so it must not be assumed safe.
  const assignments = [
    ...code.matchAll(/productionBrowserSourceMaps["'\]]*\s*[:=]\s*([^,;}\n]+)/g),
  ];
  assignments
    .map(match => match[1].trim())
    .filter(value => value !== 'false')
    .forEach(value => {
      fail(
        'C',
        `${NEXT_CONFIG} sets productionBrowserSourceMaps to \`${value}\`; that publishes ` +
          'readable application source to the CDN. Remove the key (Next defaults to false) ' +
          'or pin it to the literal false.'
      );
    });
}

// Measured on the committed bytes rather than a comment-stripped copy, because
// CloudFront receives the committed bytes: a rationale comment is as fatal to the
// publish as the code is, which is why the rationale lives under docs/ instead.
function assertEdgeFunctionsFitQuota() {
  CLOUDFRONT_FUNCTIONS.forEach(relative => {
    const source = readIfPresent(relative);
    if (source === null) {
      fail('D', `${relative} is missing; its CloudFront function size cannot be verified.`);
      return;
    }
    const bytes = Buffer.byteLength(source, 'utf8');
    if (bytes > CLOUDFRONT_FUNCTION_MAX_BYTES) {
      fail(
        'D',
        `${relative} is ${bytes} bytes, over the ${CLOUDFRONT_FUNCTION_MAX_BYTES}-byte ` +
          'CloudFront Functions quota; the infra apply would reject it and production ' +
          'would keep the previous version. Move rationale to docs/edge-routing.md rather ' +
          'than raising the limit, which AWS does not allow.'
      );
    }
  });
}

function startsPipeline(step, pipeline) {
  const run = runOf(step);
  if (!SANDBOX_PIPELINE_START.test(run)) return false;
  return new RegExp(`--name[\\s=]+["']?${pipeline}["']?(?![\\w-])`).test(run);
}

function workflowsStarting(workflows, pipeline) {
  return workflows.filter(workflow =>
    stepsOf(workflow.doc).some(step => startsPipeline(step, pipeline))
  );
}

function assertSandboxCreationOnlyOnPullRequests(workflows) {
  const creators = workflowsStarting(workflows, SANDBOX_CREATION_PIPELINE);
  if (creators.length === 0) {
    fail(
      'G',
      `no workflow under ${WORKFLOW_DIR}/ starts the "${SANDBOX_CREATION_PIPELINE}" pipeline, so ` +
        'the sandbox lifecycle cannot be audited; if provisioning moved, point this assertion ' +
        'at it.'
    );
    return;
  }
  creators.forEach(workflow => {
    const keys = triggerKeys(workflow.triggers);
    const extra = keys.filter(key => key !== SANDBOX_CREATION_TRIGGER);
    if (!keys.includes(SANDBOX_CREATION_TRIGGER) || extra.length > 0) {
      fail('G', creatorTriggerFailure(workflow.file, extra));
      return;
    }
    const types = pullRequestTypesOf(workflow.triggers);
    if (types.length !== 1 || types[0] !== SANDBOX_CREATION_TYPE) {
      fail(
        'G',
        `${WORKFLOW_DIR}/${workflow.file} starts the "${SANDBOX_CREATION_PIPELINE}" pipeline on ` +
          `${SANDBOX_CREATION_TRIGGER} types ${JSON.stringify(types)}. Keep ` +
          `"${SANDBOX_CREATION_TYPE}" as its only type so billed sandbox creation requires ` +
          'an explicit PR label and cannot race close-triggered teardown.'
      );
    }
  });
}

function pullRequestTypesOf(triggers) {
  const trigger = triggers?.[SANDBOX_CREATION_TRIGGER];
  return Array.isArray(trigger?.types) ? trigger.types.map(String) : [];
}

// A creator with no `pull_request` trigger at all (`on: {}`, or a missing `on`)
// is the other way the lifecycle breaks: nothing is orphaned, but no pull
// request ever gets a sandbox, and the workflow is still the one this gate
// located as the provisioner, so it must not read as compliant.
function creatorTriggerFailure(file, extra) {
  const head = `${WORKFLOW_DIR}/${file} starts the "${SANDBOX_CREATION_PIPELINE}" pipeline`;
  if (extra.length > 0) {
    return (
      `${head} on ${extra.join(', ')}; a sandbox provisioned outside a pull request has no ` +
      'closed event to tear it down and is billed until someone notices. Keep ' +
      `${SANDBOX_CREATION_TRIGGER} as its only trigger.`
    );
  }
  return (
    `${head} but has no ${SANDBOX_CREATION_TRIGGER} trigger at all, so no pull request is ever ` +
    `provisioned a sandbox. Give it ${SANDBOX_CREATION_TRIGGER} as its only trigger.`
  );
}

// Exactly `on: pull_request: types: [closed]` and nothing else. A missing
// `closed` never reclaims a sandbox; an extra type (`opened`) or an extra
// trigger (`workflow_dispatch`, `push`) starts the deletion pipeline while the
// pull request's sandbox is still in use, or with no pull request at all.
function tearsDownOnlyOnClose(triggers) {
  const keys = triggerKeys(triggers);
  const types = pullRequestTypesOf(triggers);
  return (
    keys.length === 1 &&
    keys[0] === SANDBOX_CREATION_TRIGGER &&
    types.length === 1 &&
    types[0] === SANDBOX_TEARDOWN_TYPE
  );
}

function assertSandboxDeletionOnPullRequestClose(workflows) {
  const deleters = workflowsStarting(workflows, SANDBOX_DELETION_PIPELINE);
  if (deleters.length === 0) {
    fail(
      'G',
      `no workflow under ${WORKFLOW_DIR}/ starts the "${SANDBOX_DELETION_PIPELINE}" pipeline, so ` +
        'every sandbox the creation pipeline provisions is orphaned; restore the teardown workflow.'
    );
    return;
  }
  deleters.forEach(workflow => {
    if (tearsDownOnlyOnClose(workflow.triggers)) return;
    fail(
      'G',
      `${WORKFLOW_DIR}/${workflow.file} starts the "${SANDBOX_DELETION_PIPELINE}" pipeline ` +
        `but is not triggered by ${SANDBOX_CREATION_TRIGGER} with "${SANDBOX_TEARDOWN_TYPE}" as ` +
        'its only type and no other trigger. Without "closed" (the default types are ' +
        'opened/synchronize/reopened) a closed pull request never reclaims its sandbox; with ' +
        'any other type or trigger the deletion pipeline runs against a sandbox still in use.'
    );
  });
}

const workflows = loadWorkflows();
const localActions = loadLocalActions();
assertPrivilegedWorkflowsAreAlerted(workflows);
assertEdgeAllowListIntact();
assertEdgeCoverageStaysPinned();
assertNoProductionSourceMaps();
assertEdgeFunctionsFitQuota();
assertRoleAssumingJobsDeclareEnvironment(workflows, localActions);
assertCredentialsMaskedBeforePersisting(workflows, localActions);
assertSandboxCreationOnlyOnPullRequests(workflows);
assertSandboxDeletionOnPullRequestClose(workflows);

if (failures.length > 0) {
  failures.forEach(failure => console.error(`::error::prod-guardrails: ${failure}`));
  process.exit(1);
}

console.log(
  `prod-guardrails: OK (${workflows.length} workflows audited, ` +
    `${localActions.size} local composite actions followed)`
);
