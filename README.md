# Dash build access

The Action exchanges a GitHub Actions OIDC proof for temporary access to a private
GitHub input repository and Nix cache. It works in approved
private repositories inside and outside the Dash organization. Access is granted
by the service's explicit repository, owner, workflow, branch and event policy;
installing the Action grants no access by itself. CI stores no App key or cache
token.

## Read private inputs

Use an ephemeral GitHub-hosted runner. Python 3 and Nix must be installed before
the exchange. The workflow owns Nix installation; this Action only configures
temporary build access. Use an upstream installer directly, pinned to a reviewed
commit and release, without persisting a GitHub token in Nix's configuration.

This example uses the Determinate Systems installer for upstream Nix. The
`determinate: false` setting preserves upstream Nix, a mode the installer vendor
does not support. The build-access Action does not require a particular Nix
distribution. The
[example checksum manifest](examples/nix-installer-v3.24.1.sha256) is data for
the upstream installer's verifier, not an installer Action. Its hashes preserve
the reviewed v3.24.1 binaries for Linux x86_64/ARM64 and macOS ARM64. An installer
update requires reviewing the release and hashes together. Other maintained
installers can be used with equivalent integrity and credential controls.

Set native `cache-mode: none` on the job to disable GitHub Actions archive
cache reads and writes. GitHub scopes the job’s cache token and supplies the
effective `ACTIONS_CACHE_MODE`; setting that environment variable alone is
insufficient because the runner can overwrite it.
A binary checksum does not protect other files extracted from a cached archive.
The upstream Action still downloads and verifies the pinned raw binary. This
setting does not disable Nix binary caches or the temporary Dash cache access.

Replace `REVIEWED_ACTION_COMMIT` with the full 40-character build-access Action
commit. Replace `REVIEWED_CHECKSUMS_COMMIT` with the full commit containing the
manifest; the installer configuration is independent of the build-access revision:

```yaml
permissions:
  contents: read
  id-token: write
  pull-requests: read # Needed when the policy permits same-repository PRs.

jobs:
  check:
    runs-on: ubuntu-latest
    cache-mode: none
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false
      - uses: DeterminateSystems/nix-installer-action@3138316df39ed29be04236d7ffc686fa525866aa # v23
        with:
          determinate: false
          github-token: ""
          source-tag: v3.24.1
          source-checksums-url: https://raw.githubusercontent.com/dash-bank/build-access-action/REVIEWED_CHECKSUMS_COMMIT/examples/nix-installer-v3.24.1.sha256
          source-checksums-sha256: e5406a23403be8ce96ce5543c26f16821abdd211960497f704e631207a84eaec
      - name: Verify Nix has no saved access tokens
        run: |
          nix config show --json | python3 -c '
          import json, sys
          if json.load(sys.stdin)["access-tokens"]["value"]:
              raise SystemExit("Nix must not retain access tokens on this runner")
          '
      - uses: dash-bank/build-access-action@REVIEWED_ACTION_COMMIT
        with:
          service-url: REPLACE_WITH_REVIEWED_SERVICE_ORIGIN
          github-repository: REPLACE_WITH_PRIVATE_OWNER_AND_REPOSITORY
          github-repository-id: REPLACE_WITH_IMMUTABLE_REPOSITORY_ID
          cache-url: REPLACE_WITH_REVIEWED_CACHE_URL
          cache-public-key: REPLACE_WITH_REVIEWED_ARTIFACT_PUBLIC_KEY
      - run: nix flake check --print-build-logs
```

The build-access Action runs before private input evaluation. It verifies the returned installation token's single target repository
and immutable ID, checks cache identity and deadlines, and uses bundled cache
setup code. It never follows service redirects or prints provider response
bodies. Credential files have mode 600; their containing delivery directory has
mode 700. GitHub masks the proof and issued credentials before further processing.

The post-job hook revokes the installation token and removes the private delivery
and cache credential files. Expiration remains the final bound when a runner is
forcibly terminated. Run the Action again to renew credentials during a long job;
an older post hook preserves files owned by the newer invocation. If a renewal
fails before replacing daemon credentials, the earlier post hook still removes
its exact credential even if the newer invocation already removed the shared
ownership marker.

## Publish cache outputs

`access: publish` requests cache read/write access only.
The service requires a separate writer rule for the signed caller identity.
Policy can trust matching workflows or require protected-branch, environment,
GitHub-hosted runner and pinned reusable-workflow controls.
Reader approval never grants uploads.

Set native `cache-mode: none` on the publishing job. Use a fresh publishing runner
after successful validation. Build outputs without
credentials using pure, sandboxed Nix evaluation and the existing publisher's
OIDC-environment isolation. Obtain access only after those builds, through pinned
controls. The bundled `dash-cache push` requires `attic` on `PATH`; install it
from a reviewed public Nix input before obtaining the writer grant. This Action
does not evaluate a private flake to obtain its cache client.

```yaml
- name: Obtain temporary cache writer
  id: access
  uses: dash-bank/build-access-action@REVIEWED_ACTION_COMMIT
  with:
    access: publish
    service-url: REPLACE_WITH_REVIEWED_SERVICE_ORIGIN
    cache-url: REPLACE_WITH_REVIEWED_CACHE_URL
    cache-public-key: REPLACE_WITH_REVIEWED_ARTIFACT_PUBLIC_KEY
- name: Upload completed outputs
  env:
    CACHE_CLIENT: ${{ steps.access.outputs.cache-client }}
  run: '"$CACHE_CLIENT" push /nix/store/REPLACE_WITH_COMPLETED_OUTPUT'
```

## Inputs and outputs

| Input                  | Requirement           | Purpose                                                               |
| ---------------------- | --------------------- | --------------------------------------------------------------------- |
| `access`               | Defaults to `read`    | Request reader access or separately authorized `publish` access.      |
| `github-token`         | `${{ github.token }}` | Runtime token sent only for private PR metadata verification.         |
| `service-url`          | Required              | Reviewed HTTPS service origin and exact OIDC audience.                |
| `github-repository`    | Required for `read`   | Expected private input repository in `owner/name` form.               |
| `github-repository-id` | Required for `read`   | Expected immutable numeric ID of that repository.                     |
| `cache-url`            | Required              | Expected HTTPS cache URL, consisting of an origin and one cache name. |
| `cache-public-key`     | Required              | Expected Nix artifact verification public key in `name:base64` form.  |

| Output              | Meaning                                                  |
| ------------------- | -------------------------------------------------------- |
| `cache-url`         | Verified private cache endpoint.                         |
| `cache-expires-at`  | UTC expiration; renew before it.                         |
| `github-expires-at` | UTC installation token expiration, empty for publishers. |
| `cache-client`      | Absolute path to the bundled `dash-cache` executable.    |

Deployment inputs have no defaults in the public source. Replace the configuration
placeholders with reviewed literal values in workflow YAML and pass them through
`with`. A private workflow limits public disclosure. Branch protection is
recommended for reviewing reader configuration changes; reader authorization
does not require it. Isolated publishing retains its separately enforced protected-branch
and environment requirements.
Missing or invalid inputs fail before an
OIDC request. Repository IDs, URLs and artifact public keys are configuration,
not credentials; they may appear in workflow logs and must not be treated as
secrets. The public payload contains no deployment identifiers or cache settings.

Prefer checked-in private workflow values when branch protection and code-owner
review protect configuration changes. Repository configuration variables can be
edited by repository writers without a workflow change; use them only when those
writers are trusted to change the service and artifact verification key.

These inputs are independent trust anchors. Never obtain them from a pull request,
an untrusted dispatch input or the exchange response. The Action compares the
returned cache URL/public key and repository name/ID against caller configuration.
The service cannot choose a different cache or repository through its response.
Review configuration and artifact public-key changes as carefully as workflow
changes. Parameterization reduces public disclosure; service policy still owns
authorization.

The Action writes a mode-600 cache settings file inside its private runtime
directory and exports its path and pinned endpoint for later `dash-cache` steps.
The bundled client requires that runtime configuration and ships no fallback
cache identity. Its post-job cleanup removes the settings with the owning
invocation's credentials. Earlier cleanup preserves a newer invocation's files.

Authenticated cache metadata is capped at 128 KiB before JSON parsing. One owned
Python worker uses the existing verified-TLS, no-redirect urllib request, and
returns only an identity verdict over a private pipe. The parent and worker
enforce the same absolute 30-second deadline, including DNS, TLS, headers and
response reads. The worker's OS alarm closes its socket and inherited output
pipes by that deadline even if the parent is killed. SIGTERM or SIGINT to the
parent also terminates and reaps the worker; bounded reaping can add at most two
seconds. A failed or timed-out check completes before existing credential or
configuration files are changed.

## Verification

In the private maintainer checkout, run
`nix develop --command bash tests/run-public-action.sh` before advancing consumer
pins. Its HTTP scenarios exercise OIDC exchange, request and response refusal,
repository scope, token masking, file permissions, cleanup and renewal. The
Node test child executable stands in for host cache installation. The harness also runs the existing cache CLI scenarios against this payload's
actual Python helper, using a real local HTTP service and temporary files.
Host service-manager calls use a command-boundary substitute. These tests do not
prove live Nix daemon setup, GitHub identity, or a signed cache restore. Run real
private-repository CI and restore a signed artifact before production cutover.
