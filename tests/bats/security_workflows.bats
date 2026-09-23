#!/usr/bin/env bats
#
# The in-repo half of the code-scanning branch-protection contract (issue #383).
#
# Branch protection is repository configuration and cannot be committed: the two
# required status checks for `main` are GitHub's native `CodeQL` check run and
# the `Analyze (typescript)` job of security-testing.yml. What the repo CAN own
# is the contract -- the wiring and the check name -- so that renaming the job,
# dropping the matrix, or losing the exec bit on the gate script fails here
# instead of silently un-gating main.

load './test_helper.bash'

WORKFLOWS_DIR="$PROJECT_ROOT/.github/workflows"
ALERT_SCRIPT="$PROJECT_ROOT/scripts/ci/ci-health-alert.sh"

# Print the body of the top-level job $2 from workflow file $1. Job keys sit at a
# two-space indent under `jobs:`, so the next two-space key ends the block. This
# keeps the assertions structural: a step added to a DIFFERENT job of the same
# file cannot satisfy them.
extract_job() {
  awk -v job="  $2:" '
    $0 == job { inside = 1; next }
    inside && /^  [A-Za-z0-9_-]+:/ { inside = 0 }
    inside { print }
  ' "$1"
}

# Print the `permissions:` mapping of the job body on stdin. Job-level keys sit
# at a four-space indent, so the next four-space key ends the block. A comment
# elsewhere in the job -- the gate step explains the grant in prose -- must not
# be able to satisfy a permission assertion.
extract_job_permissions() {
  awk '
    /^    permissions:[[:space:]]*$/ { inside = 1; next }
    inside && /^    [A-Za-z0-9_-]+:/ { inside = 0 }
    inside { print }
  '
}

# Print the code-scanning severity predicate lines shared by the gate script and
# the ci-health-alerts digest, normalised to a single space so indentation
# differences between a shell script and a YAML block scalar do not matter.
extract_severity_predicate() {
  grep -E '^[[:space:]]*\|[[:space:]]*(\(\.rule\.|select\(\$sec)' "$1" |
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]\{1,\}/ /g'
}

# Print one `<job id>|<if expression>` row per top-level job whose body mentions
# `role-to-assume`, parsed with js-yaml. This repository bans regex-scanning of
# workflow YAML (CLAUDE.md, issue #447): a substring search could not tell a real
# job-level `if:` from the same text inside a comment or a `run:` body, so a job
# that dropped the guard entirely would still pass.
role_assuming_jobs() {
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const jobs = (doc && doc.jobs) || {};
    for (const [id, job] of Object.entries(jobs)) {
      if (!JSON.stringify(job || null).includes("role-to-assume")) continue;
      const guard = job && typeof job.if === "string" ? job.if : "";
      process.stdout.write(id + "|" + guard.replace(/\s+/g, " ").trim() + "\n");
    }
  ' "$1"
}

# Print one `<job id>|<step index>|<uses value>` row per `uses:` in the workflow,
# job-level and step-level alike, parsed with js-yaml. Only the real `uses` VALUE
# is emitted, so a mutable ref that merely mentions a sha in its trailing comment
# — `uses: vendor/action@main # pinned to <sha>` — is reported as `@main`.
workflow_uses() {
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const jobs = (doc && doc.jobs) || {};
    for (const [id, job] of Object.entries(jobs)) {
      if (job && typeof job.uses === "string") {
        process.stdout.write(id + "|-|" + job.uses + "\n");
      }
      const steps = (job && job.steps) || [];
      steps.forEach((step, i) => {
        if (step && typeof step.uses === "string") {
          process.stdout.write(id + "|" + i + "|" + step.uses + "\n");
        }
      });
    }
  ' "$1"
}

# A reference is pinned only when the ref itself is 40 hex characters. A local
# action (`./.github/actions/<name>`) carries no ref and is pinned by the commit
# the workflow itself runs at.
assert_all_uses_pinned() {
  local file="$1" rows row ref
  rows="$(workflow_uses "$file")"
  [ -n "$rows" ] || return 0
  while read -r row; do
    ref="${row#*|}"
    ref="${ref#*|}"
    case "$ref" in
      ./*) continue ;;
    esac
    if ! printf '%s' "$ref" |
      grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*@[0-9a-f]{40}$'; then
      printf 'unpinned uses in %s: %s\n' "$file" "$row" >&2
      return 1
    fi
  done < <(printf '%s\n' "$rows")
}

@test "the analyze job runs the code-scanning gate and the script is executable" {
  local analyze
  analyze="$(extract_job "$WORKFLOWS_DIR/security-testing.yml" analyze)"

  [[ "$analyze" == *'run: ./scripts/ci/code-scanning-gate.sh'* ]]
  # The workflow invokes the path directly, so a lost exec bit is a silent CI
  # break that no YAML assertion would catch.
  [ -x "$PROJECT_ROOT/scripts/ci/code-scanning-gate.sh" ]
}

@test "the gate step is fed entirely through env, never interpolated into run" {
  local analyze
  analyze="$(extract_job "$WORKFLOWS_DIR/security-testing.yml" analyze)"

  [[ "$analyze" == *'EVENT_NAME: ${{ github.event_name }}'* ]]
  [[ "$analyze" == *'PR_NUMBER: ${{ github.event.pull_request.number }}'* ]]
  [[ "$analyze" == *'HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}'* ]]
  [[ "$analyze" == *'ANALYSIS_SHA: ${{ github.sha }}'* ]]
  # Script injection guard: the only run: line in the gate step is the bare
  # script invocation, with no ${{ }} anywhere in it.
  [[ "$analyze" != *'run: ./scripts/ci/code-scanning-gate.sh ${{'* ]]
}

@test "the analyze job still produces the required 'Analyze (typescript)' check name" {
  # The required-check name is `name:` + the matrix value. Renaming the job,
  # changing name:, or adding a language renames the check run and GitHub
  # silently stops requiring anything.
  local analyze
  analyze="$(extract_job "$WORKFLOWS_DIR/security-testing.yml" analyze)"

  [[ "$analyze" == *'name: Analyze'* ]]
  [[ "$analyze" == *"language: ['typescript']"* ]]
  # Exactly one language, or the check name gains a sibling and drifts.
  [ "$(grep -c "language: \['typescript'\]" "$WORKFLOWS_DIR/security-testing.yml")" -eq 1 ]
}

@test "the analyze job keeps the security-events permission the gate reads with" {
  local perms
  perms="$(extract_job "$WORKFLOWS_DIR/security-testing.yml" analyze |
    extract_job_permissions)"

  # write subsumes read, so no separate grant is needed -- but losing it would
  # break both the upload and the gate.
  [ -n "$perms" ]
  printf '%s\n' "$perms" | grep -qE '^      security-events: write[[:space:]]*$'
}

@test "ci-health-alerts monitors security testing and ignores pull-request runs" {
  local file="$WORKFLOWS_DIR/ci-health-alerts.yml"

  grep -Fq '      - security testing' "$file"
  # security testing runs on pull_request too; both workflow_run steps must
  # refuse to file or close a tracking issue for a PR run.
  [ "$(grep -c "github.event.workflow_run.event != 'pull_request'" "$file")" -eq 2 ]
  grep -Fq 'security-events: read' "$file"
}

@test "ci-health-alerts keeps the recovery guard and the red-main sweep" {
  local file="$WORKFLOWS_DIR/ci-health-alerts.yml"

  # Out-of-order (stale) success events must not close an issue a newer failed
  # run opened, and the daily red-main sweep must survive this change. The guard
  # itself lives in the script the workflow calls (issues #325, #329, #331).
  grep -Fq 'gh run list --workflow "$WORKFLOW_NAME" --branch main --limit 1' "$ALERT_SCRIPT"
  grep -Fq 'name: Sweep for a red default branch' "$file"
  grep -Fq "if: github.event_name == 'schedule'" "$file"
}

@test "ci-health-alerts leaves the non-security alert bodies byte-identical" {
  # The digest is appended as ${suffix}, which is empty for every workflow other
  # than security testing, so the deploy/release wording is unchanged.
  grep -Fq -e '"Still failing: ${RUN_URL}${suffix}"' "$ALERT_SCRIPT"
  grep -Fq -e '"The '"'"'$WORKFLOW_NAME'"'"' workflow failed. Latest run: ${RUN_URL}${suffix}"' "$ALERT_SCRIPT"
  grep -Fq 'if [ "$WORKFLOW_NAME" = "security testing" ]; then' "$ALERT_SCRIPT"
}

@test "the ci-health-alerts digest uses the same severity predicate as the gate" {
  # Two copies of the blocking-alert rule exist by necessity: the gate script
  # renders a TSV for the PR check while the alert script renders an issue
  # digest, and the two jq programs differ after the predicate. Pin the shared
  # lines together so a change to one is a visible failure rather than a silent
  # divergence.
  local gate alerts
  gate="$(extract_severity_predicate "$PROJECT_ROOT/scripts/ci/code-scanning-gate.sh")"
  alerts="$(extract_severity_predicate "$ALERT_SCRIPT")"

  [ -n "$gate" ]
  [ "$gate" = "$alerts" ]
}

# Print one `<index>|<name>|<run>` row per step of the `alert` job, parsed with
# js-yaml. Same reason as role_assuming_jobs: a substring search could not tell a
# real `run:` from the same text inside a comment.
alert_job_steps() {
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const steps = (doc && doc.jobs && doc.jobs.alert && doc.jobs.alert.steps) || [];
    steps.forEach((step, i) => {
      const run = typeof step.run === "string" ? step.run.trim() : "";
      process.stdout.write(i + "|" + (step.name || "") + "|" + run + "\n");
    });
  ' "$1"
}

@test "ci-health-alerts gives every gh call a repository context at job level" {
  # The fail-open this closes (issues #325, #329, #331): for its first ~100 runs
  # the job had no checkout and no GH_REPO, so every gh call died with `failed
  # to run git: fatal: not a git repository` and no alert was ever filed. The
  # value must be the real job-level env entry, read with js-yaml, not a string
  # that could be satisfied from a comment.
  local file="$WORKFLOWS_DIR/ci-health-alerts.yml" rows row run
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const env = doc.jobs.alert.env || {};
    if (env.GH_REPO !== "${{ github.repository }}") {
      console.error("jobs.alert.env.GH_REPO must be ${{ github.repository }}, got " +
        JSON.stringify(env.GH_REPO));
      process.exit(1);
    }
    if (env.GH_TOKEN !== "${{ github.token }}") {
      console.error("jobs.alert.env.GH_TOKEN must be ${{ github.token }}");
      process.exit(1);
    }
  ' "$file"

  # Every step that runs anything runs the script -- the bare invocation, with
  # nothing interpolated -- so the bats-covered code path is the only code path.
  rows="$(alert_job_steps "$file")"
  [ -n "$rows" ]
  while read -r row; do
    run="${row##*|}"
    [ -z "$run" ] || [ "$run" = 'bash scripts/ci/ci-health-alert.sh' ]
  done < <(printf '%s\n' "$rows")
  [ "$(printf '%s\n' "$rows" | grep -c '|bash scripts/ci/ci-health-alert.sh$')" -eq 4 ]
  [ -x "$ALERT_SCRIPT" ]
}

@test "ci-health-alerts checks the script out without credentials and can dry-run from a branch" {
  local file="$WORKFLOWS_DIR/ci-health-alerts.yml"

  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const steps = doc.jobs.alert.steps;
    const checkout = steps.find(s => typeof s.uses === "string" && s.uses.startsWith("actions/checkout@"));
    if (!checkout || checkout.with["persist-credentials"] !== false) {
      console.error("the checkout must set persist-credentials: false");
      process.exit(1);
    }
    if (checkout.with["sparse-checkout"] !== "scripts/ci/ci-health-alert.sh") {
      console.error("the checkout must be sparse on the alert script");
      process.exit(1);
    }
    // A pinned ref: main would make a dispatch from a branch run the OLD script,
    // so the dry run could never prove the change under review.
    if (checkout.with.ref !== undefined) {
      console.error("the checkout must not pin ref:");
      process.exit(1);
    }
    // YAML 1.1 folds a bare `on:` key to boolean true; js-yaml v4 keeps it a
    // string. Read both so the assertion is parser-agnostic.
    const triggers = doc.on || doc[true] || {};
    const dispatch = triggers.workflow_dispatch;
    if (!dispatch || !dispatch.inputs || dispatch.inputs.dry_run === undefined) {
      console.error("workflow_dispatch must declare a dry_run input");
      process.exit(1);
    }
    if (dispatch.inputs.dry_run.type !== "boolean" || dispatch.inputs.dry_run.default !== true) {
      console.error("dry_run must be a boolean input defaulting to true");
      process.exit(1);
    }
    const manual = steps.find(s => s.if === "github.event_name == '"'"'workflow_dispatch'"'"'");
    if (!manual || manual.env.ALERT_DRY_RUN !== "${{ inputs.dry_run && '"'"'1'"'"' || '"'"'0'"'"' }}") {
      console.error("the dispatch step must map inputs.dry_run onto ALERT_DRY_RUN");
      process.exit(1);
    }
  ' "$file"
}

@test "every action in the security workflows is pinned to a full commit sha" {
  local file
  for file in "$WORKFLOWS_DIR/security-testing.yml" "$WORKFLOWS_DIR/ci-health-alerts.yml"; do
    assert_all_uses_pinned "$file"
  done
}

# --- Sandbox workflows: the prod-account trust boundary (issue #375) ------------
#
# `sandbox-creating.yml` and `sandbox-deleting.yml` assume roles in the
# PRODUCTION AWS account. These properties keep that reachable only from a
# reviewed, same-repo pull request, and each one has been absent from this
# repository at some point in its history.
#
# There is deliberately NO assertion that these jobs declare an `environment:`.
# Naming one changes the minted OIDC subject to
# `repo:VilnaCRM-Org/website:environment:<name>`, which the deployed sandbox role
# trust policy does not accept -- see .github/sandbox_workflows.md, "Order of
# operations".

sandbox_workflows() {
  printf '%s\n' \
    "$WORKFLOWS_DIR/sandbox-creating.yml" \
    "$WORKFLOWS_DIR/sandbox-deleting.yml"
}

# Assert the WORKFLOW-level `permissions:` of $1 is a real, empty mapping.
# Parsed with js-yaml for the reason CLAUDE.md gives (issue #447): a text scan
# for `permissions: {}` is satisfied by the same characters in a comment or a
# `run:` body, so a workflow that lost the baseline entirely would still pass.
assert_root_permissions_empty() {
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const perms = doc && doc.permissions;
    const empty =
      perms !== null &&
      typeof perms === "object" &&
      !Array.isArray(perms) &&
      Object.keys(perms).length === 0;
    if (!empty) {
      console.error(
        process.argv[1] +
          ": workflow-level permissions must be an empty mapping, got " +
          JSON.stringify(perms === undefined ? "<absent>" : perms)
      );
      process.exit(1);
    }
  ' "$1"
}

# Assert the real `concurrency.cancel-in-progress` of $1 is the boolean false.
# Same parser, same reason: aborting an in-flight AWS pipeline trigger mid-run
# is unsafe, and a reassuring string in a step body must not certify it.
assert_not_cancelling() {
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const fs = require("fs");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const concurrency = (doc && doc.concurrency) || undefined;
    const value =
      concurrency && typeof concurrency === "object"
        ? concurrency["cancel-in-progress"]
        : undefined;
    if (value !== false) {
      console.error(
        process.argv[1] +
          ": concurrency.cancel-in-progress must be false, got " +
          JSON.stringify(value === undefined ? "<absent>" : value)
      );
      process.exit(1);
    }
  ' "$1"
}

SAME_REPO_GUARD='github.event.pull_request.head.repo.full_name == github.repository'

# Assert every role-assuming job in $1 carries the same-repo guard as its real
# job-level `if:` field.
assert_same_repo_guard() {
  local file="$1" rows row
  rows="$(role_assuming_jobs "$file")"
  [ -n "$rows" ] || return 0
  while read -r row; do
    if [[ "${row#*|}" != *"$SAME_REPO_GUARD"* ]]; then
      printf 'unguarded role-assuming job in %s: %s\n' "$file" "$row" >&2
      return 1
    fi
  done < <(printf '%s\n' "$rows")
}

@test "every sandbox job that assumes a role carries the same-repo guard" {
  # A fork PR receives no OIDC id-token, so the role assumption would fail --
  # but it would fail LOUDLY on every fork PR, and the guard is what states the
  # boundary rather than relying on that side effect.
  local file
  while read -r file; do
    assert_same_repo_guard "$file"
  done < <(sandbox_workflows)
}

@test "sandbox creation requires deploy-sandbox on an open pull request" {
  # A labeled event can still be delivered for a closed PR. Both role-assuming
  # jobs must reject that state so a late label cannot recreate a torn-down
  # sandbox, while commits remain free of sandbox-triggered AWS executions.
  PROJECT_ROOT="$PROJECT_ROOT" node -e '
    const fs = require("fs");
    const yaml = require(process.env.PROJECT_ROOT + "/node_modules/js-yaml");
    const doc = yaml.load(fs.readFileSync(process.argv[1], "utf8"));
    const types = doc.on && doc.on.pull_request && doc.on.pull_request.types;
    if (JSON.stringify(types) !== JSON.stringify(["labeled"])) process.exit(1);
    for (const job of ["check-tokens", "deploy"]) {
      const condition = doc.jobs && doc.jobs[job] && doc.jobs[job].if;
      for (const required of [
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.event.pull_request.state == '\''open'\''",
        "github.event.label.name == '\''deploy-sandbox'\''",
      ]) {
        if (!condition || !condition.includes(required)) process.exit(1);
      }
    }
  ' "$WORKFLOWS_DIR/sandbox-creating.yml"
}

@test "the same-repo guard assertion rejects a guard that exists only in a comment" {
  # The shape the old substring search let through: the job-level `if:` is gone,
  # and the guard text survives only in a comment and a `run:` body.
  local fixture="$BATS_TEST_TMPDIR/comment-guard.yml"
  cat >"$fixture" <<'YAML'
name: unguarded
on:
  pull_request:
jobs:
  deploy:
    # if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - run: echo "github.event.pull_request.head.repo.full_name == github.repository"
      - uses: aws-actions/configure-aws-credentials@517a711dbcd0e402f90c77e7e2f81e849156e31d # v6.2.2
        with:
          role-to-assume: arn:aws:iam::1:role/r
YAML

  run assert_same_repo_guard "$fixture"
  [ "$status" -ne 0 ]

  # Restoring the real job-level field passes, so the assertion is not vacuous.
  sed -i 's|^    # if: |    if: |' "$fixture"
  run assert_same_repo_guard "$fixture"
  [ "$status" -eq 0 ]
}

@test "the sandbox workflows are reachable only from pull_request events" {
  # A bare `push:` trigger is the #375 F1 path: any branch push reaching the
  # production account with no pull request and therefore no review.
  local file triggers
  while read -r file; do
    triggers="$(awk '/^on:/ { inside = 1; next }
                     inside && /^[A-Za-z]/ { inside = 0 }
                     inside && /^  [A-Za-z_]+:/ { print }' "$file")"
    [ -n "$triggers" ]
    printf '%s\n' "$triggers" | grep -qE '^  pull_request:'
    # Exactly one trigger, and it is the pull_request one.
    [ "$(printf '%s\n' "$triggers" | wc -l)" -eq 1 ]
  done < <(sandbox_workflows)
}

@test "every action in the sandbox workflows is pinned to a full commit sha" {
  local file
  while read -r file; do
    assert_all_uses_pinned "$file"
  done < <(sandbox_workflows)
}

@test "the sha-pin assertion rejects a mutable ref that names a sha in its comment" {
  # The shape the old line-regex let through: the ref is a branch, and the
  # 40-hex string lives in the trailing comment where it pins nothing.
  local fixture="$BATS_TEST_TMPDIR/mutable-ref.yml"
  cat >"$fixture" <<'YAML'
name: mutable
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        uses: vendor/action@main # was vendor/action@3d3c42e5aac5ba805825da76410c181273ba90b1
YAML

  run assert_all_uses_pinned "$fixture"
  [ "$status" -ne 0 ]

  # The same step on a real sha ref passes, so the assertion is not vacuous.
  sed -i 's|@main # was vendor/action@|@|' "$fixture"
  run assert_all_uses_pinned "$fixture"
  [ "$status" -eq 0 ]
}

@test "the sandbox workflows keep permissions least-privilege and non-cancelling" {
  local file
  while read -r file; do
    assert_root_permissions_empty "$file"
    assert_not_cancelling "$file"
  done < <(sandbox_workflows)
}

@test "the workflow-level permissions assertion rejects a baseline that exists only in a comment" {
  # The shape the old `grep -Fq 'permissions: {}'` let through: the real
  # workflow-level baseline is absent (so a new job inherits the repository
  # default), and the text survives only in a comment.
  local fixture="$BATS_TEST_TMPDIR/comment-permissions.yml"
  cat >"$fixture" <<'YAML'
name: commented baseline
on:
  pull_request:
# permissions: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML

  # The old text scan is satisfied by the fixture, so this case is a real
  # differential rather than a restatement of the parsed assertion.
  grep -Fq 'permissions: {}' "$fixture"
  run assert_root_permissions_empty "$fixture"
  [ "$status" -ne 0 ]

  # A broader real baseline is rejected too, so the check is about the value.
  sed -i 's|^# permissions: {}$|permissions:\n  contents: write|' "$fixture"
  run assert_root_permissions_empty "$fixture"
  [ "$status" -ne 0 ]

  # And the real empty mapping passes, so the assertion is not vacuous.
  printf 'name: baseline\non:\n  pull_request:\npermissions: {}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' >"$fixture"
  run assert_root_permissions_empty "$fixture"
  [ "$status" -eq 0 ]
}

@test "the cancel-in-progress assertion rejects the setting appearing only in a run body" {
  # The shape the old `grep -Fq 'cancel-in-progress: false'` let through: the
  # real concurrency block cancels in flight, and the reassuring text is a line
  # of shell output inside a step.
  local fixture="$BATS_TEST_TMPDIR/run-body-concurrency.yml"
  cat >"$fixture" <<'YAML'
name: cancelling
on:
  pull_request:
permissions: {}
concurrency:
  group: cancelling-${{ github.ref }}
  cancel-in-progress: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: 'echo "cancel-in-progress: false"'
YAML

  grep -Fq 'cancel-in-progress: false' "$fixture"
  run assert_not_cancelling "$fixture"
  [ "$status" -ne 0 ]

  # A workflow with no concurrency block at all is rejected as well.
  local missing="$BATS_TEST_TMPDIR/no-concurrency.yml"
  printf 'name: none\non:\n  pull_request:\npermissions: {}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' >"$missing"
  run assert_not_cancelling "$missing"
  [ "$status" -ne 0 ]

  # The real setting passes, so the assertion is not vacuous.
  sed -i 's|  cancel-in-progress: true|  cancel-in-progress: false|' "$fixture"
  run assert_not_cancelling "$fixture"
  [ "$status" -eq 0 ]
}
