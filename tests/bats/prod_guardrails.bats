#!/usr/bin/env bats
#
# Coverage for scripts/ci/lint-prod-guardrails.mjs (issues #383, #375 and #380).
#
# The seven invariants this gate protects only ever hold in production, where no
# other PR check watches them: a privileged workflow whose failure nobody is told
# about, an edge handler that quietly reverts to passing every path to the S3
# origin, browser source maps published to the CDN, a CloudFront Function source
# too large for the service to publish, a role-assuming job with no environment
# protection in front of it, a credential persisted to $GITHUB_ENV before it
# is masked out of the log, and a sandbox provisioned by an event that no
# teardown ever pairs with. A gate for that class of
# regression is only worth having if it is red on the exact regression, so every
# case below copies the REAL repository files into a fixture and mutates exactly
# one invariant.

load './test_helper.bash'

setup() {
  FIXTURE="$BATS_TEST_TMPDIR/repo"
  mkdir -p "$FIXTURE/scripts"
  cp -R "$PROJECT_ROOT/.github" "$FIXTURE/.github"
  cp "$PROJECT_ROOT/jest.config.ts" "$FIXTURE/jest.config.ts"
  cp "$PROJECT_ROOT/next.config.js" "$FIXTURE/next.config.js"
  cp "$PROJECT_ROOT/scripts/cloudfront_routing.js" "$FIXTURE/scripts/cloudfront_routing.js"
  cp "$PROJECT_ROOT/scripts/cloudfront_security_headers.js" \
    "$FIXTURE/scripts/cloudfront_security_headers.js"
}

# Grows a fixture file by exactly $2 bytes of block comment. Comments are the
# point: CloudFront uploads the file as written, so a rationale paragraph counts
# against the quota exactly as code does.
pad_with_comment() {
  local file="$1" bytes="$2"
  python3 - "$file" "$bytes" <<'PY'
import sys
path, bytes_wanted = sys.argv[1], int(sys.argv[2])
filler = '/*' + 'x' * (bytes_wanted - 5) + '*/\n'
assert len(filler.encode()) == bytes_wanted
with open(path, 'a', encoding='utf-8') as fh:
    fh.write(filler)
PY
}

run_guardrails() {
  run node "$PROJECT_ROOT/scripts/ci/lint-prod-guardrails.mjs" "$FIXTURE"
}

# --- Happy path ----------------------------------------------------------------

@test "passes against the committed repository" {
  run_guardrails
  [ "$status" -eq 0 ]
  assert_output_contains 'prod-guardrails: OK'
  assert_output_contains 'workflows audited'
  # The dev-container composite is the one local action; it must be followed,
  # not skipped, for assertions D and E to have seen its steps.
  assert_output_contains '1 local composite actions followed'
}

# --- Assertion A: privileged workflows must be alerted on ----------------------

@test "fails when a privileged workflow drops out of the alert list" {
  # deploy.yml assumes the production AWS role on push to main. Removing its
  # `name:` from ci-health-alerts.yml's workflow_run list is exactly the drift
  # that leaves a broken production deploy unreported.
  local alerts="$FIXTURE/.github/workflows/ci-health-alerts.yml"
  grep -q '^      - website$' "$alerts"
  sed -i '/^      - website$/d' "$alerts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'deploy.yml'
  assert_output_contains 'assumes an AWS role'
  assert_output_contains 'on.workflow_run.workflows'
}

@test "fails when a privileged workflow is renamed without updating the alert list" {
  # The coupling that surprises contributors: `name:` is load-bearing, because
  # workflow_run matches on it.
  sed -i '0,/^name: website$/s//name: website deploy/' "$FIXTURE/.github/workflows/deploy.yml"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'website deploy'
}

@test "accepts a new privileged workflow once it is added to the alert list" {
  sed -i '0,/^name: website$/s//name: website deploy/' "$FIXTURE/.github/workflows/deploy.yml"
  sed -i 's/^      - website$/      - website deploy/' "$FIXTURE/.github/workflows/ci-health-alerts.yml"

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "exempts a privileged workflow that only runs on pull requests" {
  # A PR-scoped failure is already visible as a red check on the pull request,
  # so it needs no separate alert. sandbox-creating.yml relies on this.
  cat >"$FIXTURE/.github/workflows/pr-only-privileged.yml" <<'YAML'
name: pr only privileged
on:
  pull_request:
    branches:
      - main
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::1234:role/example
YAML

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "fails on an unwatched privileged workflow added on a push trigger" {
  cat >"$FIXTURE/.github/workflows/rogue-deploy.yml" <<'YAML'
name: rogue deploy
on:
  push:
    branches:
      - main
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::1234:role/example
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'rogue deploy'
}

@test "accepts a release-cutting workflow when a release-audit workflow exists" {
  # A workflow that only cuts releases is covered by any workflow listening on
  # `release` — that is the audit path release-audit.yml provides.
  cat >"$FIXTURE/.github/workflows/rogue-release.yml" <<'YAML'
name: rogue release
on:
  push:
    branches:
      - main
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1.0.0
YAML

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "fails on a release-cutting workflow when no release audit is present" {
  rm -f "$FIXTURE/.github/workflows/release-audit.yml"
  cat >"$FIXTURE/.github/workflows/rogue-release.yml" <<'YAML'
name: rogue release
on:
  push:
    branches:
      - main
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1.0.0
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'rogue release'
  assert_output_contains 'creates a GitHub release'
}

@test "a privileged workflow cannot vouch for itself via its own release trigger" {
  # Review finding: collectAlertCoverage used to scan every workflow including the
  # one under audit, so a workflow that both cut a release and listened on
  # `release` satisfied its own audit requirement.
  rm -f "$FIXTURE/.github/workflows/release-audit.yml"
  cat >"$FIXTURE/.github/workflows/self-vouching.yml" <<'YAML'
name: self vouching
on:
  push:
    branches:
      - main
  release:
    types:
      - published
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - run: gh release create v1.0.0
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'self vouching'
}

@test "a workflow that cannot reach a human does not count as alert coverage" {
  # Listing a name under workflow_run is not enough: without issues: write the
  # listener can file nothing, so nobody is told.
  sed -i '/^      - website$/d' "$FIXTURE/.github/workflows/ci-health-alerts.yml"
  cat >"$FIXTURE/.github/workflows/fake-listener.yml" <<'YAML'
name: fake listener
on:
  workflow_run:
    workflows:
      - website
    types:
      - completed
jobs:
  noop:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo "I cannot open an issue"
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'deploy.yml'
}

@test "detects a role assumed through the AWS CLI rather than the action" {
  cat >"$FIXTURE/.github/workflows/cli-role.yml" <<'YAML'
name: cli role
on:
  push:
    branches:
      - main
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: aws sts assume-role --role-arn arn:aws:iam::1234:role/example --role-session-name s
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'cli role'
}

@test "fails when the allow-list tables are declared with const instead of var" {
  # The freeze audit used to match `var` only, so switching to const dropped the
  # ALLOWED_* tables out of the immutability check entirely.
  sed -i 's/^var ALLOWED_DIRS = Object.freeze({$/const ALLOWED_DIRS = ({/' \
    "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'ALLOWED_DIRS'
  assert_output_contains 'mutable'
}

@test "fails when map is added to the edge extension allow-list" {
  sed -i "s/^  js: true,$/  js: true,\n  map: true,/" "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'ALLOWED_EXTENSIONS'
  assert_output_contains 'source maps'
}

@test "an origin fallthrough cannot hide behind a missing semicolon or a comment" {
  # ASI makes a bare `return request` valid, and a trailing comment used to break
  # the end-of-block anchor.
  python3 - "$FIXTURE/scripts/cloudfront_routing.js" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('    return buildNotFoundResponse();\n',
              '    return request // fall back to the origin\n')
open(p, 'w').write(s)
PY

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'unconditional'
}

@test "fails when source maps are enabled by assignment rather than a literal key" {
  python3 - "$FIXTURE/next.config.js" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s += "\nmodule.exports.productionBrowserSourceMaps = true;\n"
open(p, 'w').write(s)
PY

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'productionBrowserSourceMaps'
}

@test "reports an unparseable workflow instead of crashing the whole gate" {
  # A duplicate key or bad indent must not take assertions B and C down with it,
  # which is what an uncaught js-yaml throw would do.
  printf 'name: broken\non:\n  push:\njobs:\n  a:\n    permissions:\n      issues: write\n      issues: write\n' \
    >"$FIXTURE/.github/workflows/broken.yml"
  sed -i 's/statusCode: 404,/statusCode: 200,/' "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'broken.yml is not valid YAML'
  # The later assertions still ran.
  assert_output_contains '[B]'
}

@test "fails when the workflow directory is missing entirely" {
  rm -rf "$FIXTURE/.github/workflows"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'is missing'
}

# --- Assertion D: role-assuming jobs off pull_request need an environment ------

@test "fails when deploy.yml drops its environment key" {
  # deploy.yml is the one job that assumes a role on a non-pull_request trigger
  # (push to main) and the one that declares an environment. Losing the key is
  # the #375 F2 regression: the production trigger runs with no reviewer, wait
  # timer or deployment-branch rule in front of it.
  local deploy="$FIXTURE/.github/workflows/deploy.yml"
  grep -q '^    environment:$' "$deploy"
  sed -i '/^    environment:$/,/^      url: /d' "$deploy"
  ! grep -q 'environment' "$deploy"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'deploy.yml job "deploy"'
  assert_output_contains 'reachable from push'
  assert_output_contains 'declares no environment'
  # The remedy names the trap that bit PR #464, not just the missing key.
  assert_output_contains 'sts:AssumeRoleWithWebIdentity'
}

@test "fails when a sandbox workflow regains a push trigger" {
  # The #375 F1 regression: `push: branches-ignore: [main]` reached the
  # production account from any branch push. The sandbox jobs are exempt only
  # while pull_request is their sole trigger.
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i '0,/^on:$/s//on:\n  push:\n    branches-ignore:\n      - main/' "$sandbox"
  grep -q '^  push:$' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'sandbox-creating.yml job "check-tokens"'
  assert_output_contains 'sandbox-creating.yml job "deploy"'
  assert_output_contains 'reachable from push'
}

@test "an environment key that survives only in a comment does not count" {
  # The parser never sees a comment, so commenting the block out is the same
  # regression as deleting it -- and the one a substring search would miss.
  local deploy="$FIXTURE/.github/workflows/deploy.yml"
  sed -i '/^    environment:$/,/^      url: /s/^/# /' "$deploy"
  grep -q '^#     environment:$' "$deploy"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'deploy.yml job "deploy"'
}

@test "accepts an environment given as a plain string" {
  local deploy="$FIXTURE/.github/workflows/deploy.yml"
  sed -i '/^    environment:$/,/^      url: /d' "$deploy"
  sed -i '0,/^    steps:$/s//    environment: production\n    steps:/' "$deploy"
  grep -q '^    environment: production$' "$deploy"

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "rejects an environment mapping that names no environment" {
  # `environment: { url: ... }` is a label with nothing to attach protection
  # rules to. GitHub itself rejects it, but the gate must not wait for a run
  # on main to say so.
  local deploy="$FIXTURE/.github/workflows/deploy.yml"
  sed -i '/^      name: production$/d' "$deploy"
  grep -q '^    environment:$' "$deploy"
  ! grep -q 'name: production' "$deploy"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'deploy.yml job "deploy"'
}

@test "pull_request_target is not exempt from the environment gate" {
  # Only `pull_request` mints the subject the sandbox trap is about.
  # pull_request_target runs with the base repository's secrets on a
  # fork-authored change, which is the opposite of a reason to exempt it.
  cat >"$FIXTURE/.github/workflows/target-role.yml" <<'YAML'
name: target role
on:
  pull_request_target:
    types:
      - labeled
jobs:
  provision:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::1234:role/example
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'target-role.yml job "provision"'
  assert_output_contains 'reachable from pull_request_target'
}

@test "follows a local composite action that assumes the role" {
  # Moving the login step into a composite must not move it out of the audit.
  # The workflow is added to the alert list so assertion A stays quiet and the
  # verdict here is D's alone.
  mkdir -p "$FIXTURE/.github/actions/aws-login"
  cat >"$FIXTURE/.github/actions/aws-login/action.yml" <<'YAML'
name: aws login
runs:
  using: composite
  steps:
    - uses: aws-actions/configure-aws-credentials@v6
      with:
        role-to-assume: arn:aws:iam::1234:role/example
YAML
  cat >"$FIXTURE/.github/workflows/nightly-sync.yml" <<'YAML'
name: nightly sync
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/aws-login
      - run: aws s3 sync out/ s3://bucket
YAML
  sed -i 's/^      - website$/      - website\n      - nightly sync/' \
    "$FIXTURE/.github/workflows/ci-health-alerts.yml"

  run_guardrails
  [ "$status" -eq 1 ]
  refute_output_contains '[A]'
  assert_output_contains '[E]'
  assert_output_contains 'nightly-sync.yml job "sync"'

  # The same job with an environment passes, so the composite walk is not what
  # turned it red.
  sed -i 's/^    runs-on: ubuntu-latest$/    runs-on: ubuntu-latest\n    environment: staging/' \
    "$FIXTURE/.github/workflows/nightly-sync.yml"
  run_guardrails
  [ "$status" -eq 0 ]
}

@test "fails closed on a local action it cannot read" {
  # A `uses: ./...` with no action.yml behind it would otherwise be a job the
  # gate has silently declared role-free.
  cat >"$FIXTURE/.github/workflows/opaque.yml" <<'YAML'
name: opaque
on:
  workflow_dispatch:
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/does-not-exist
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[E]'
  assert_output_contains 'opaque.yml job "run"'
  assert_output_contains 'does-not-exist'
  assert_output_contains 'cannot prove'
}

@test "a pull_request-only job needs no environment even through a composite" {
  # The exemption is the OIDC-subject trap and nothing else, so it must hold
  # for the composite spelling of the login too -- the sandbox jobs could be
  # refactored that way without turning this gate red.
  mkdir -p "$FIXTURE/.github/actions/aws-login"
  cat >"$FIXTURE/.github/actions/aws-login/action.yml" <<'YAML'
name: aws login
runs:
  using: composite
  steps:
    - uses: aws-actions/configure-aws-credentials@v6
      with:
        role-to-assume: arn:aws:iam::1234:role/example
YAML
  cat >"$FIXTURE/.github/workflows/pr-composite-login.yml" <<'YAML'
name: pr composite login
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  sandbox:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/aws-login
YAML

  run_guardrails
  [ "$status" -eq 0 ]
}

# --- Assertion F: credentials are masked before they are persisted -------------

# A pull_request-only workflow with one job, so assertions A and D have nothing
# to say and the verdict is E's alone. $1 is the run body, indented as a YAML
# block scalar; $2 (optional) is a second step's run body.
write_persisting_workflow() {
  local first="$1" second="${2-}"
  {
    printf 'name: persisting\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n'
    printf '      - name: first\n        run: |\n'
    printf '%s\n' "$first" | sed 's/^/          /'
    if [ -n "$second" ]; then
      printf '      - name: second\n        run: |\n'
      printf '%s\n' "$second" | sed 's/^/          /'
    fi
  } >"$FIXTURE/.github/workflows/persisting.yml"
}

@test "fails when a token is written to GITHUB_ENV without a preceding mask" {
  # The #375 F4 regression: the Secrets-Manager token used to be appended to
  # $GITHUB_ENV in the clear, where any later `set -x`, env dump or errored
  # step would have printed it.
  write_persisting_workflow 'GITHUB_TOKEN=$(aws secretsmanager get-secret-value --query SecretString --output text | jq -r .token)
echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'persisting.yml job "build" step 1 ("first")'
  assert_output_contains 'writes GITHUB_TOKEN to $GITHUB_ENV'
  assert_output_contains '::add-mask::'
}

@test "accepts a token that is masked before it is written" {
  write_persisting_workflow 'GITHUB_TOKEN=$(get-token)
echo "::add-mask::$GITHUB_TOKEN"
echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "GITHUB_OUTPUT is a sink too" {
  # A step output is rendered into every consumer's expression context and
  # job summary, so it needs the same mask as an environment variable.
  write_persisting_workflow 'echo "token=$(get-token)" >> "$GITHUB_OUTPUT"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes token to $GITHUB_OUTPUT'
}

@test "a mask in a later step does not cover an earlier write" {
  # By the time the second step runs, the first has already logged and
  # persisted the value.
  write_persisting_workflow 'echo "API_TOKEN=$(get-token)" >> "$GITHUB_ENV"' \
    'echo "::add-mask::$API_TOKEN"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'step 1 ("first")'
  refute_output_contains 'step 2 ("second")'
}

@test "a mask printed after the write on the same line does not count" {
  write_persisting_workflow 'echo "API_TOKEN=$t" >> "$GITHUB_ENV"; echo "::add-mask::$t"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes API_TOKEN'
}

@test "a mask that survives only in a shell comment does not count" {
  # Commenting the mask out is the cheapest way to disable it while leaving
  # the text on disk for a substring search to find.
  write_persisting_workflow '# echo "::add-mask::$t"
echo "API_TOKEN=$t" >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes API_TOKEN'
}

@test "a mask of an unrelated value does not cover the credential that is persisted" {
  # Review finding on #375: the first cut set a boolean once any ::add-mask::
  # had printed, so masking a build id and then persisting $secret in the
  # clear passed. The mask must name the value the write persists.
  write_persisting_workflow 'echo "::add-mask::$BUILD_ID"
echo "API_TOKEN=$secret" >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes API_TOKEN to $GITHUB_ENV'
  assert_output_contains 'for secret'
  assert_output_contains 'A mask of some other value does not cover it'

  # The braced and quoted spellings of the same variable are one value.
  write_persisting_workflow 'echo "::add-mask::${secret}"
echo "API_TOKEN=$secret" >> "$GITHUB_ENV"'
  run_guardrails
  [ "$status" -eq 0 ]
}

@test "a printf placeholder is resolved to the argument it prints" {
  write_persisting_workflow 'echo "::add-mask::$p"
printf '"'"'DB_PASSWORD=%s\n'"'"' "$p" | tee -a "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 0 ]

  # Masking a different argument does not cover the one the format prints.
  write_persisting_workflow 'echo "::add-mask::$q"
printf '"'"'DB_PASSWORD=%s\n'"'"' "$p" | tee -a "$GITHUB_ENV"'
  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'writes DB_PASSWORD'
}

@test "a read of GITHUB_ENV or GITHUB_OUTPUT is not a write" {
  # Review finding on #375: any mention of the file used to count as a write,
  # so `test -w "$GITHUB_ENV"` was reported as persisting an unknown variable.
  write_persisting_workflow 'test -w "$GITHUB_ENV" || exit 1
grep -q "^API_TOKEN=" "$GITHUB_ENV" && echo "already exported"
cat "$GITHUB_OUTPUT"'

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "the PowerShell and cmd spellings of the write are caught" {
  write_persisting_workflow '"NPM_TOKEN=$t" | Out-File -FilePath $env:GITHUB_ENV -Append
Add-Content -Path $env:GITHUB_OUTPUT -Value "DB_PASSWORD=$p"
echo API_SECRET=%s%>>%GITHUB_ENV%'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'writes NPM_TOKEN'
  assert_output_contains 'writes DB_PASSWORD'
  assert_output_contains 'writes API_SECRET'
}

@test "a variable not named like a credential may be written unmasked" {
  # The existing GITHUB_OUTPUT writers on the tree (a drift status, a spec
  # list, a build matrix) are exactly this shape and must stay green.
  write_persisting_workflow 'echo "expires_at=$(date -u +%s)" >> "$GITHUB_ENV"
echo "drift=$status" >>"$GITHUB_OUTPUT"'

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "the tee, printf and unquoted spellings are all caught" {
  write_persisting_workflow 'printf '"'"'DB_PASSWORD=%s\n'"'"' "$p" | tee -a "$GITHUB_ENV"
echo NPM_TOKEN=$t >>$GITHUB_ENV
echo "AWS_SECRET_ACCESS_KEY=$k" >> "${GITHUB_ENV}"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'writes DB_PASSWORD'
  assert_output_contains 'writes NPM_TOKEN'
  assert_output_contains 'writes AWS_SECRET_ACCESS_KEY'
}

@test "the multi-line NAME<<EOF form inside a grouped write is caught" {
  # The shape dockerfile-performance.yml uses for a non-secret body: the name
  # is on a line inside the group and the redirection is on the closing brace.
  write_persisting_workflow '{
  echo '"'"'PRIVATE_KEY<<KEY_EOF'"'"'
  cat key.pem
  echo '"'"'KEY_EOF'"'"'
} >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes PRIVATE_KEY'
}

@test "a heredoc redirected into GITHUB_ENV is read line by line" {
  write_persisting_workflow 'cat >> "$GITHUB_ENV" <<EOF
REGION=eu-central-1
AWS_CREDENTIAL_FILE=$c
EOF'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'writes AWS_CREDENTIAL_FILE'
}

@test "a write whose variable the gate cannot read fails closed" {
  # `cat file >> "$GITHUB_ENV"` persists whatever the file holds; the gate
  # cannot see the names, so it reports the write rather than guessing.
  write_persisting_workflow 'cat generated.env >> "$GITHUB_ENV"'

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains 'cannot tell which variable it persists'

  # Masking first makes the same write acceptable, so the fail-closed branch
  # is not a dead end.
  write_persisting_workflow 'echo "::add-mask::$(cat generated.env)"
cat generated.env >> "$GITHUB_ENV"'
  run_guardrails
  [ "$status" -eq 0 ]
}

@test "the run steps of a local composite action are audited too" {
  mkdir -p "$FIXTURE/.github/actions/leaky"
  cat >"$FIXTURE/.github/actions/leaky/action.yml" <<'YAML'
name: leaky
runs:
  using: composite
  steps:
    - name: persist
      shell: bash
      run: echo "REGISTRY_TOKEN=$(get-token)" >> "$GITHUB_ENV"
YAML

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[F]'
  assert_output_contains '.github/actions/leaky/action.yml'
  assert_output_contains 'writes REGISTRY_TOKEN'
}

# --- Assertion B: the edge handler must stay fail-closed -----------------------

@test "fails when the edge handler reverts to origin pass-through" {
  # The literal regression this PR fixes: before issue #383 the handler's try
  # block ended in an unconditional `return request`.
  cat >"$FIXTURE/scripts/cloudfront_routing.js" <<'JS'
'use strict';
var ROUTE_MAP = Object.freeze({ '/': '/index.html' });
function handler(event) {
  var request = event.request;
  try {
    if (Object.prototype.hasOwnProperty.call(ROUTE_MAP, request.uri)) {
      request.uri = ROUTE_MAP[request.uri];
      return request;
    }
    return request;
  } catch (err) {
    return request;
  }
}
JS

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'unconditional'
  assert_output_contains 'fail closed'
}

@test "fails when an allow-list map is no longer frozen" {
  sed -i 's/^var ALLOWED_DIRS = Object.freeze({$/var ALLOWED_DIRS = ({/' \
    "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'ALLOWED_DIRS'
  assert_output_contains 'mutable'
}

@test "fails when an asset allow-list table is deleted outright" {
  # Deleting a table slips past the freeze audit, which only inspects the tables it
  # finds. The handler still reads ALLOWED_FILES, and the file is 'use strict', so
  # the missing binding throws inside the try and the catch hands every path to the
  # origin -- the exact pass-through this assertion exists to prevent.
  python3 - "$FIXTURE/scripts/cloudfront_routing.js" <<'PY'
import re
import sys
p = sys.argv[1]
s = open(p).read()
open(p, 'w').write(re.sub(r'var ALLOWED_FILES = Object\.freeze\(\{[\s\S]*?\n\}\);\n', '', s))
PY

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'ALLOWED_FILES'
  assert_output_contains 'no longer declares'
}

@test "fails when the synthetic 404 response is removed" {
  sed -i 's/statusCode: 404,/statusCode: 200,/' "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'synthetic 404'
}

@test "fails when the edge handler is missing" {
  rm -f "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'cloudfront_routing.js is missing'
}

@test "fails when the edge script is dropped from the 100% coverage layer" {
  # Unpinning coverage first would let a later routing regression land unnoticed,
  # so the pin itself is part of the contract.
  # Repoint just the routing entry. EDGE_COVERAGE_FROM became a multi-entry array
  # when #377 added cloudfront_security_headers.js to the same 100% layer, so match
  # the quoted entry rather than the whole declaration -- a declaration-shaped
  # pattern silently stops mutating the fixture and the test passes vacuously.
  sed -i "s#'<rootDir>/scripts/cloudfront_routing.js'#'<rootDir>/scripts/other.js'#" \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'no longer collects edge coverage'
}

@test "fails when the coverage entry is repointed outside the repository" {
  # An entry that merely ends in the same tail collects nothing from this file, and
  # Jest filters the coverage map by collectCoverageFrom, so the 100% edge layer then
  # measures zero files and passes vacuously while both it and this gate stay green.
  sed -i "s#'<rootDir>/scripts/cloudfront_routing.js'#'<rootDir>/../../other/scripts/cloudfront_routing.js'#" \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'no longer collects edge coverage'
}

@test "a negated coverage glob does not count as a live pin" {
  # A leading `!` tells Jest to EXCLUDE the file, which is the opposite of a pin.
  sed -i "s#'<rootDir>/scripts/cloudfront_routing.js'#'!<rootDir>/scripts/cloudfront_routing.js'#" \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'no longer collects edge coverage'
}

@test "fails when an edge coverage threshold drops below 100" {
  sed -i '/const EDGE_COVERAGE_THRESHOLD/,/};/ s/branches: 100/branches: 95/' \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'threshold branches at 100'
}

@test "a commented-out coverage entry does not count as a live pin" {
  # The pin used to be read off the raw file, so commenting the entry out left the
  # gate green while Jest had already stopped collecting from the edge script.
  sed -i "s#^  '<rootDir>/scripts/cloudfront_routing.js',#  // '<rootDir>/scripts/cloudfront_routing.js',#" \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'no longer collects edge coverage'
}

@test "a commented-out threshold does not mask a lowered live one" {
  # Keeping the 100% line as a comment above a lowered live one satisfied the
  # `branches: 100` search while the enforced floor was 95.
  sed -i '/const EDGE_COVERAGE_THRESHOLD/,/^};/ s#^  global: { branches: 100,#  // global: { branches: 100,\n  global: { branches: 95,#' \
    "$FIXTURE/jest.config.ts"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'threshold branches at 100'
}

# --- Assertion C: no production browser source maps ----------------------------

@test "fails when productionBrowserSourceMaps is enabled" {
  sed -i "s/  output: 'export',/  output: 'export',\n  productionBrowserSourceMaps: true,/" \
    "$FIXTURE/next.config.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'productionBrowserSourceMaps'
  assert_output_contains 'publishes'
}

@test "accepts productionBrowserSourceMaps pinned explicitly to false" {
  sed -i "s/  output: 'export',/  output: 'export',\n  productionBrowserSourceMaps: false,/" \
    "$FIXTURE/next.config.js"

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "ignores a commented-out mention of the source-map option" {
  sed -i "s|  output: 'export',|  output: 'export',\n  // productionBrowserSourceMaps: true would publish sources.|" \
    "$FIXTURE/next.config.js"

  run_guardrails
  [ "$status" -eq 0 ]
}

# --- Assertion G: the sandbox lifecycle is symmetric ---------------------------

@test "fails when the sandbox creator provisions on a bare branch push" {
  # The #380 F2 finding: `push: branches-ignore: [main]` provisioned a billed
  # AWS environment for every branch, and only a pull request closing ever
  # reaches the deletion pipeline, so a branch that never opened one leaked
  # its sandbox indefinitely. Assertion E reports the same trigger for the
  # missing environment; G names the orphaning on its own.
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i '0,/^on:$/s//on:\n  push:\n    branches-ignore:\n      - main/' "$sandbox"
  grep -q '^  push:$' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-creating.yml starts the "sandbox-creation" pipeline on push'
  assert_output_contains 'no closed event to tear it down'
}

@test "a manual dispatch of the sandbox creator is orphaning too" {
  # workflow_dispatch has no pull request behind it either, so the same
  # environment is created with nothing to close it.
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i '0,/^on:$/s//on:\n  workflow_dispatch:/' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'pipeline on workflow_dispatch'
}

@test "fails when the sandbox creator has no trigger at all" {
  # Review finding on #482: an empty `on:` mapping produced no "extra" trigger,
  # so the located provisioner passed while never being able to run for a pull
  # request. A missing `on:` reaches the parser the same way.
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i '/^on:$/,/^    types: \[labeled\]$/c\on: {}' "$sandbox"
  grep -q '^on: {}$' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-creating.yml starts the "sandbox-creation" pipeline'
  assert_output_contains 'no pull_request trigger at all'
}

@test "fails when the sandbox creator accepts an automatic PR event" {
  # Only an explicit label may incur the sandbox cost; synchronize would put
  # every later commit back on the paid creation path.
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i 's/^    types: \[labeled\]$/    types: [labeled, synchronize]/' "$sandbox"
  grep -q 'labeled, synchronize\]' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-creating.yml starts the "sandbox-creation" pipeline on pull_request types ["labeled","synchronize"]'
  assert_output_contains 'Keep "labeled" as its only type'
}

@test "fails when the sandbox creator is triggered by push instead of pull_request" {
  local sandbox="$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i 's/^  pull_request:$/  push:/' "$sandbox"
  grep -q '^  push:$' "$sandbox"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'pipeline on push'
}

@test "fails when the sandbox deleter drops closed from its pull_request types" {
  local deleter="$FIXTURE/.github/workflows/sandbox-deleting.yml"
  sed -i 's/^      - closed$/      - reopened/' "$deleter"
  grep -q '^      - reopened$' "$deleter"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-deleting.yml starts the "sandbox-deletion" pipeline'
  assert_output_contains '"closed" as its only type'
}

@test "fails when the sandbox deleter adds a second pull_request type beside closed" {
  # Review finding on #482: `types: [closed, opened]` still contains `closed`,
  # but the `opened` event starts the deletion pipeline against the sandbox the
  # creation workflow is provisioning for that same pull request.
  local deleter="$FIXTURE/.github/workflows/sandbox-deleting.yml"
  sed -i 's/^      - closed$/      - closed\n      - opened/' "$deleter"
  grep -q '^      - opened$' "$deleter"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-deleting.yml starts the "sandbox-deletion" pipeline'
  assert_output_contains 'no other trigger'
}

@test "fails when the sandbox deleter gains a trigger beside pull_request" {
  # A workflow_dispatch run has no pull request number to hand the pipeline;
  # a push run would tear down the sandbox of whichever pull request the branch
  # belongs to on every commit.
  local deleter="$FIXTURE/.github/workflows/sandbox-deleting.yml"
  sed -i '0,/^on:$/s//on:\n  workflow_dispatch:/' "$deleter"
  grep -q '^  workflow_dispatch:$' "$deleter"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'sandbox-deleting.yml starts the "sandbox-deletion" pipeline'
}

@test "a bare pull_request trigger on the deleter does not count as closed" {
  # Without an explicit types list GitHub runs on opened/synchronize/reopened
  # only, so the workflow would fire on every push to the PR and never on the
  # close that reclaims the sandbox.
  local deleter="$FIXTURE/.github/workflows/sandbox-deleting.yml"
  sed -i '/^on:$/,/^      - closed$/c\on: [pull_request]' "$deleter"
  grep -q '^on: \[pull_request\]$' "$deleter"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains '"closed" as its only type'
}

@test "fails closed when no workflow starts the sandbox-deletion pipeline" {
  rm "$FIXTURE/.github/workflows/sandbox-deleting.yml"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'no workflow under .github/workflows/ starts the "sandbox-deletion" pipeline'
}

@test "fails closed when no workflow starts the sandbox-creation pipeline" {
  # A lifecycle the gate cannot see must not pass vacuously: a renamed
  # pipeline or a provisioning step moved behind a wrapper has to be pointed
  # at explicitly.
  sed -i 's/--name "sandbox-creation"/--name "environment-creation"/' \
    "$FIXTURE/.github/workflows/sandbox-creating.yml"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[G]'
  assert_output_contains 'no workflow under .github/workflows/ starts the "sandbox-creation" pipeline'
}

@test "the --name= spelling and a continuation line both identify the pipeline" {
  # The committed deleter already splits `--name` onto a continuation line; the
  # creator is rewritten to the `--name=` form so both spellings are proved.
  sed -i 's/--name "sandbox-creation"/--name=sandbox-creation/' \
    "$FIXTURE/.github/workflows/sandbox-creating.yml"
  grep -q -- '--name=sandbox-creation' "$FIXTURE/.github/workflows/sandbox-creating.yml"

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "a pipeline name that merely starts with sandbox-creation does not count" {
  sed -i 's/--name "sandbox-creation"/--name "sandbox-creation-legacy"/' \
    "$FIXTURE/.github/workflows/sandbox-creating.yml"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'no workflow under .github/workflows/ starts the "sandbox-creation" pipeline'
}

# --- Reporting -----------------------------------------------------------------

@test "reports every violation in a single run rather than stopping at the first" {
  local before
  sed -i '/^      - website$/d' "$FIXTURE/.github/workflows/ci-health-alerts.yml"
  sed -i '/^    environment:$/,/^      url: /d' "$FIXTURE/.github/workflows/deploy.yml"
  write_persisting_workflow 'echo "API_TOKEN=$t" >> "$GITHUB_ENV"'
  sed -i '0,/^on:$/s//on:\n  workflow_dispatch:/' "$FIXTURE/.github/workflows/sandbox-creating.yml"
  sed -i 's/statusCode: 404,/statusCode: 200,/' "$FIXTURE/scripts/cloudfront_routing.js"
  sed -i "s/  output: 'export',/  output: 'export',\n  productionBrowserSourceMaps: true,/" \
    "$FIXTURE/next.config.js"
  before=$(wc -c <"$FIXTURE/scripts/cloudfront_routing.js")
  pad_with_comment "$FIXTURE/scripts/cloudfront_routing.js" $((10001 - before))

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[A]'
  assert_output_contains '[B]'
  assert_output_contains '[C]'
  assert_output_contains '[D]'
  assert_output_contains '[E]'
  assert_output_contains '[F]'
  assert_output_contains '[G]'
}

@test "a block comment cannot hide map in the edge extension allow-list" {
  # Review finding: `map/* x */: true` satisfied the table syntax while evading a
  # naive `map\s*:` test, so every structural check now runs on a comment-stripped
  # copy of the source.
  sed -i "s|^  js: true,$|  js: true,\n  map/* not a real extension */: true,|" \
    "$FIXTURE/scripts/cloudfront_routing.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'ALLOWED_EXTENSIONS'
  assert_output_contains 'source maps'
}

@test "a comment containing a brace cannot truncate the extension table capture" {
  # A `})` inside a comment would end the non-greedy table capture early, hiding
  # anything after it from the map check.
  python3 - "$FIXTURE/scripts/cloudfront_routing.js" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('  css: true,', '  /* closes early: }) */\n  css: true,\n  map: true,')
open(p, 'w').write(s)
PY

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains 'source maps'
}

# --- Assertion D: every CloudFront Function must fit the 10 KB quota ------------

@test "fails when the routing function outgrows the CloudFront Functions quota" {
  # This is the regression that shipped: three merged PRs grew the routing script
  # to ~13 KB of mostly comments, so the infra apply could not publish it and the
  # distribution kept the previous version — `/en` rewrote in git and 404'd on
  # the CDN.
  local before
  before=$(wc -c <"$FIXTURE/scripts/cloudfront_routing.js")
  pad_with_comment "$FIXTURE/scripts/cloudfront_routing.js" $((10001 - before))
  [ "$(wc -c <"$FIXTURE/scripts/cloudfront_routing.js")" -eq 10001 ]

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[D]'
  assert_output_contains 'scripts/cloudfront_routing.js is 10001 bytes'
  assert_output_contains 'CloudFront Functions quota'
}

@test "accepts a function that sits exactly on the quota boundary" {
  local before
  before=$(wc -c <"$FIXTURE/scripts/cloudfront_routing.js")
  pad_with_comment "$FIXTURE/scripts/cloudfront_routing.js" $((10000 - before))
  [ "$(wc -c <"$FIXTURE/scripts/cloudfront_routing.js")" -eq 10000 ]

  run_guardrails
  [ "$status" -eq 0 ]
}

@test "the quota is measured in bytes, not characters" {
  # A multi-byte comment can stay under 10,000 characters while exceeding 10,000
  # bytes, and bytes are what the CloudFront API receives.
  python3 - "$FIXTURE/scripts/cloudfront_routing.js" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding='utf-8') as fh:
    source = fh.read()
chars_left = 9_990 - len(source)
filler = '/*' + '—' * (chars_left - 4) + '*/\n'
padded = source + filler
assert len(padded) < 10_000, len(padded)
assert len(padded.encode('utf-8')) > 10_000, len(padded.encode('utf-8'))
with open(path, 'w', encoding='utf-8') as fh:
    fh.write(padded)
PY

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[D]'
  assert_output_contains 'scripts/cloudfront_routing.js'
}

@test "the security-headers function is held to the same quota" {
  local before
  before=$(wc -c <"$FIXTURE/scripts/cloudfront_security_headers.js")
  pad_with_comment "$FIXTURE/scripts/cloudfront_security_headers.js" $((10001 - before))

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[D]'
  assert_output_contains 'scripts/cloudfront_security_headers.js is 10001 bytes'
}

@test "fails when the security-headers function is missing" {
  rm "$FIXTURE/scripts/cloudfront_security_headers.js"

  run_guardrails
  [ "$status" -eq 1 ]
  assert_output_contains '[D]'
  assert_output_contains 'scripts/cloudfront_security_headers.js is missing'
}
