# Temporary build access

Exchange GitHub Actions OIDC identity for selected private GitHub sources and Nix
cache permissions. Server policy decides access. Installing this Action grants nothing.
Install Nix separately through an upstream installer.

## Configure

Pin the published Action to a reviewed full commit. Supply reviewed resource
names, repository IDs, cache URLs and artifact keys through workflow configuration.
The example resource values below are placeholders. Use this Action with a
service implementing the resource API; older Action revisions use a different contract.

```yaml
permissions:
  contents: read
  id-token: write
  pull-requests: read # when private same-repository PRs are allowed

jobs:
  build:
    runs-on: ubuntu-latest
    cache-mode: none
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      - name: Install Nix
        uses: cachix/install-nix-action@13d8dd58da0234aa297dedd986986ccb8e7f3e24 # v31.11.1
        with:
          github_access_token: ${{ github.token }}
      - uses: dash-bank/build-access-action@9b6ba7eea710bae82bb6c03f56acae876725bcfa
        with:
          service-url: https://access.example
          flakes: |
            {"shared-ui":{"repository":"example/shared-ui","repository_id":"12345","owner_id":"67890"}}
          caches: |
            {"shared":{"url":"https://cache.example/shared","public_key":"REVIEWED_KEY","access":"read"}}
      - run: nix build .#application
```

| Input          | Meaning                                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------------------- |
| `service-url`  | Required HTTPS service origin and OIDC audience                                                         |
| `flakes`       | JSON map of registered source names to expected `repository`, `repository_id`, `owner_id`; default `{}` |
| `caches`       | JSON map of cache names to expected `url`, `public_key`, `access`; default `{}`                         |
| `github-token` | Runtime workflow token for private PR verification; defaults to `github.token`                          |

Request at least one resource. Each cache requests `read` or `read-write`.
Omit `flakes` for cache-only access. Omit `caches` for source-only access.
Several sources and caches can be requested together; the complete request must be authorized.
Caches must share one canonical origin because one credential covers their namespace permissions.
All names resolve through server-owned configuration. IDs and trust anchors cannot
come from PR content, dispatch input or the exchange response.

## Adopt from cachix/install-nix-action

Keep Cachix with `github_access_token: ${{ github.token }}` and a reviewed full
commit, as shown above. Run this Action after installation and before evaluating
private inputs. No token-removal step or switch to another installer is required.
Another installer is supported when it provides upstream Nix >= 2.34.

The installer token remains configured for normal GitHub fetches. It cannot read
other private repositories. This Action adds a separate repository-scoped token
for each approved source; Nix selects the longest matching prefix.
An unowned token at an exact requested repository prefix is refused before exchange.
Renewal replaces only Action-owned source tokens and preserves other credentials.
Keep this Action's default `github-token` for private PR verification.
Use the temporary job token; do not add a PAT or deploy key.

## Build and upload

Obtain source/cache reads before evaluating the flake. Request cache writes only
after successful validation and the isolated build, in the publishing context
required by policy. Do not carry credentials or executable state between jobs.

```yaml
- uses: dash-bank/build-access-action@9b6ba7eea710bae82bb6c03f56acae876725bcfa
  id: publishing
  with:
    service-url: https://access.example
    caches: |
      {"project":{"url":"https://cache.example/project","public_key":"REVIEWED_KEY","access":"read-write"}}
- shell: bash
  env:
    CACHE_CLIENT: ${{ steps.publishing.outputs.cache-client }}
  run: '"$CACHE_CLIENT" push --cache project /nix/store/REVIEWED_BUILT_STORE_PATH'
```

`dash-cache status --cache NAME` verifies a configured namespace.
`dash-cache push --cache NAME PATH...` uploads explicit built store paths and closures;
`attic` must already be installed. Selection is required when several caches are configured.
Permissions apply to the entire namespace. Source files included in uploaded
closures are readable by everyone who can read that namespace.

## Runtime and cleanup

Use fresh GitHub-hosted Linux/macOS runners with Python 3 and upstream Nix.
Source access requires Nix >= 2.34 for [repository-specific token prefixes](https://nix.dev/manual/nix/2.34/command-ref/conf-file#conf-access-tokens).
The Action preserves existing Nix access tokens and refuses unowned exact repository-prefix conflicts.
Use the GitHub flake fetcher (`github:OWNER/REPO`); SSH inputs need separate authentication.
Each returned source token is independently checked for exact repository scope.
Post-job cleanup revokes only received source tokens and removes owned private files
and matching daemon credentials. Credentials never belong in flake URLs, lockfiles,
derivations, artifacts, command arguments or logs.
Repeat the Action before expiration. Renewal may replace only Action-owned cache files.
A failed request fails the job; do not use `continue-on-error` for access setup.

Outputs: `cache-urls` (newline-separated), `cache-expires-at`, `github-expires-at`
(earliest source expiration), and `cache-client`. Credential values are never outputs.
Developer login, cache administration and Nix installation remain separate.
