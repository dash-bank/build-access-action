import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { appendFile, chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const maxResponseBytes = 65536;
const apiHeaders = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'dash-build-access' };

function input(env, name, fallback = '') {
  return env[`INPUT_${name.toUpperCase()}`] || fallback;
}

function secret(value, name) {
  if (typeof value !== 'string' || !value || value.length > 16384 || /\s/.test(value)) {
    throw new Error(`Invalid ${name} credential received`);
  }
  return value;
}

function escapeCommand(value) {
  return String(value).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}

function mask(log, value) {
  log(`::add-mask::${escapeCommand(value)}`);
}

function origin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Build-access service must be an HTTPS origin'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Build-access service must be an HTTPS origin');
  }
  return url.origin;
}

function configuration(env, access) {
  const broker = origin(input(env, 'service-url'));
  let cacheURL;
  try { cacheURL = new URL(input(env, 'cache-url')); } catch { throw new Error('Cache configuration requires an HTTPS cache URL'); }
  if (cacheURL.protocol !== 'https:' || cacheURL.username || cacheURL.password || cacheURL.search || cacheURL.hash || !/^\/[A-Za-z0-9_-]+$/.test(cacheURL.pathname)) {
    throw new Error('Cache configuration requires an HTTPS URL with one cache name');
  }
  const publicKey = input(env, 'cache-public-key');
  const encodedKey = publicKey.split(':')[1];
  if (!/^[A-Za-z0-9_-]+:[A-Za-z0-9+/]{43}=$/.test(publicKey) || /\s/.test(publicKey) || Buffer.from(encodedKey || '', 'base64').toString('base64') !== encodedKey) {
    throw new Error('Cache configuration requires a valid artifact public key');
  }
  const repository = input(env, 'github-repository');
  const repositoryId = input(env, 'github-repository-id');
  if (access === 'read' && (!/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(repository) || /\s/.test(repository) || !/^[1-9][0-9]*$/.test(repositoryId) || !Number.isSafeInteger(Number(repositoryId)))) {
    throw new Error('Reader configuration requires a repository name and immutable numeric repository ID');
  }
  return {
    broker, repository, repositoryId: Number(repositoryId),
    cacheURL: `${cacheURL.origin}${cacheURL.pathname}`,
    // Python's urlsplit hostname and netrc omit IPv6 URL brackets.
    cacheHost: cacheURL.hostname.startsWith('[') ? cacheURL.hostname.slice(1, -1) : cacheURL.hostname,
    cache: { endpoint: cacheURL.origin, cache: cacheURL.pathname.slice(1), public_key: publicKey },
  };
}

async function exists(file) {
  try { await lstat(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

async function jsonRequest(url, { method = 'GET', headers = {}, body, empty = false, acceptUnauthorized = false } = {}) {
  let response;
  try {
    response = await fetch(url, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(30000) });
  } catch {
    throw new Error('Build-access HTTPS request failed');
  }
  if (!response.ok && !(acceptUnauthorized && response.status === 401)) {
    await response.body?.cancel();
    throw new Error(`Build-access request refused (HTTP ${response.status})`);
  }
  if (empty) { await response.body?.cancel(); return; }
  let size = 0;
  const chunks = [];
  try {
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxResponseBytes) throw new Error('Response too large');
      chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new Error('Invalid build-access response');
  }
}

function expires(value, name, maxLifetime) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || parsed <= Date.now() + 30000 || parsed > Date.now() + maxLifetime) {
    throw new Error(`Invalid ${name} credential expiration`);
  }
  return new Date(parsed).toISOString();
}

async function privateWrite(file, value) {
  await writeFile(file, value, { mode: 0o600 });
  await chmod(file, 0o600);
}

async function appendWorkflow(file, name, value) {
  if (!file) throw new Error('GitHub Actions workflow file is unavailable');
  const delimiter = `DASH_BUILD_ACCESS_${randomUUID()}`;
  await appendFile(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`, { mode: 0o600 });
  await chmod(file, 0o600);
}

async function loadState(directory, env) {
  const runnerTemp = env.RUNNER_TEMP ? await realpath(env.RUNNER_TEMP) : '';
  if (!env.RUNNER_TEMP || !path.isAbsolute(directory) || path.dirname(directory) !== runnerTemp || !path.basename(directory).startsWith('dash-build-access-')) {
    throw new Error('Refusing an invalid build-access cleanup directory');
  }
  if (!await exists(directory)) return null;
  if ((await realpath(directory)) !== directory || !(await lstat(directory)).isDirectory()) {
    throw new Error('Refusing an invalid build-access cleanup directory');
  }
  return JSON.parse(await readFile(path.join(directory, 'credentials.json'), 'utf8'));
}

async function prepareCacheRoot(cacheRoot, env) {
  if (!await exists(cacheRoot)) return false;
  // Repeating this action can renew credentials, but must never replace a
  // developer's or another cache client's configuration.
  try {
    const previous = (await readFile(path.join(cacheRoot, '.build-access-owner'), 'utf8')).trim();
    const state = await loadState(previous, env);
    if (state?.cacheRoot === cacheRoot) return true;
  } catch { /* An existing unowned directory is refused below. */ }
  throw new Error('Refusing existing cache credentials; use an ephemeral runner');
}

async function runCommand(command, args, env, description) {
  try {
    return await execute(command, args, { env, timeout: 1200000, maxBuffer: 1048576 });
  } catch {
    // Child output can include credentials; never reflect it into an annotation.
    throw new Error(`${description} failed; child output withheld to protect credentials`);
  }
}

async function removeOwnedCache(state, directory, env, systemNetrc) {
  let owner = '';
  try {
    owner = (await readFile(path.join(state.cacheRoot, '.build-access-owner'), 'utf8')).trim();
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  // The directory marker owns shared configuration, not an earlier daemon
  // credential. A failed renewal can remove the marker before an older hook
  // runs. Preserve an identical token only when a live newer invocation owns it.
  let tokenOwnedByNewerInvocation = false;
  if (owner && owner !== directory) {
    const current = await loadState(owner, env);
    tokenOwnedByNewerInvocation = current?.cacheRoot === state.cacheRoot
      && current?.cache_host === state.cache_host && current?.cache_token === state.cache_token;
  }
  if (!tokenOwnedByNewerInvocation && state.cache_token && await exists(systemNetrc)) {
    let current;
    try { current = await readFile(systemNetrc, 'utf8'); } catch (error) {
      if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error;
      current = (await runCommand('sudo', ['-n', 'cat', systemNetrc], env, 'Cache credential cleanup')).stdout;
    }
    const expected = `machine ${state.cache_host} login token password ${state.cache_token}\n`;
    if (current === expected) {
      try { await unlink(systemNetrc); } catch (error) {
        if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error;
        await runCommand('sudo', ['-n', 'rm', '-f', '--', systemNetrc], env, 'Cache credential cleanup');
      }
    }
  }
  if (owner === directory) await rm(state.cacheRoot, { recursive: true, force: true });
}

export async function cleanup(env = process.env, options = {}) {
  const directory = env.STATE_directory;
  if (!directory) return;
  const state = await loadState(directory, env);
  if (!state) return;
  let failed = false;
  try {
    if (state.github_token) {
      await jsonRequest(`${options.endpoints?.github || 'https://api.github.com'}/installation/token`, {
        method: 'DELETE', headers: { ...apiHeaders, Authorization: `Bearer ${state.github_token}` }, empty: true, acceptUnauthorized: true,
      });
    }
  } catch { failed = true; }
  try {
    if (state.cacheRoot) await removeOwnedCache(state, directory, env, options.systemNetrc || '/etc/nix/dash-cache.netrc');
  } catch { failed = true; }
  await rm(directory, { recursive: true, force: true });
  if (failed) throw new Error('Temporary credential cleanup or GitHub token revocation failed');
}

export async function run(env = process.env, options = {}) {
  const log = options.log || ((line) => process.stdout.write(`${line}\n`));
  if (env.GITHUB_ACTIONS !== 'true' || env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    throw new Error('Build access requires an ephemeral GitHub-hosted runner');
  }
  if (!env.RUNNER_TEMP || !env.HOME || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || !env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    throw new Error('GitHub OIDC is unavailable; grant id-token: write to this job');
  }
  const access = input(env, 'access', 'read');
  if (!['read', 'publish'].includes(access)) throw new Error('Build access must be read or publish');
  const expected = configuration(env, access);
  await runCommand('nix', ['--version'], env, 'Installed Nix check');
  const broker = expected.broker;
  const oidcURL = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  // GitHub's request endpoint is runner-specific; the signed token's issuer is
  // separately verified by the gateway. The toolkit likewise uses this URL
  // supplied by the runner, rather than constructing it from the issuer.
  const fixtureOrigin = options.endpoints?.oidcOrigin;
  const githubOIDC = oidcURL.protocol === 'https:' && oidcURL.hostname.endsWith('.actions.githubusercontent.com') && !oidcURL.port && !oidcURL.username && !oidcURL.password && !oidcURL.hash;
  if (fixtureOrigin ? oidcURL.origin !== fixtureOrigin : !githubOIDC) {
    throw new Error('Unexpected GitHub OIDC endpoint');
  }
  oidcURL.searchParams.set('audience', broker);
  const cacheRoot = path.join(env.XDG_CONFIG_HOME || path.join(env.HOME, '.config'), 'dash-dev-env/cache');
  if (!path.isAbsolute(cacheRoot)) throw new Error('Cache configuration directory must be absolute');
  const renewsOwnedCache = await prepareCacheRoot(cacheRoot, env);
  if (!renewsOwnedCache && await exists(options.systemNetrc || '/etc/nix/dash-cache.netrc')) {
    throw new Error('Refusing existing daemon cache credentials; use an ephemeral runner');
  }
  const stateDirectory = await mkdtemp(path.join(await realpath(env.RUNNER_TEMP), 'dash-build-access-'));
  await chmod(stateDirectory, 0o700);
  const stateFile = path.join(stateDirectory, 'credentials.json');
  const state = { cacheRoot };
  await privateWrite(stateFile, JSON.stringify(state));
  await appendWorkflow(env.GITHUB_STATE, 'directory', stateDirectory);
  try {
    const identity = await jsonRequest(oidcURL, { headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
    const proof = secret(identity?.value, 'OIDC');
    mask(log, proof);
    const payload = { access };
    if (env.GITHUB_EVENT_NAME === 'pull_request') payload.github_token = secret(input(env, 'github-token'), 'workflow');
    const grant = await jsonRequest(`${options.endpoints?.broker || broker}/v1/exchange`, {
      method: 'POST', headers: { Authorization: `Bearer ${proof}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    // Mask all received credentials before validating anything that may fail.
    for (const field of ['github_token', 'cache_token']) if (typeof grant?.[field] === 'string') mask(log, grant[field]);
    if (grant?.github_token) {
      state.github_token = secret(grant.github_token, 'GitHub');
      await privateWrite(stateFile, JSON.stringify(state));
    }
    const expectedFields = ['cache_token', 'cache_expires_at', 'cache_url', 'cache_public_key', ...(access === 'read' ? ['github_token', 'github_expires_at'] : [])];
    if (!grant || typeof grant !== 'object' || Array.isArray(grant) || Object.keys(grant).some((field) => !expectedFields.includes(field)) || expectedFields.some((field) => typeof grant[field] !== 'string')) {
      throw new Error('Build access returned an unexpected credential response');
    }
    if (access === 'read' && !state.github_token) throw new Error('Build access omitted its GitHub credential');
    const cacheToken = secret(grant?.cache_token, 'cache');
    state.cache_token = cacheToken;
    await privateWrite(stateFile, JSON.stringify(state));
    const cacheExpires = expires(grant.cache_expires_at, 'cache', 1830000);
    const githubExpires = state.github_token ? expires(grant.github_expires_at, 'GitHub', 3630000) : '';
    const settings = expected.cache;
    if (grant.cache_url !== expected.cacheURL || grant.cache_public_key !== settings.public_key) {
      throw new Error('Build access returned an unexpected cache identity');
    }
    state.cache_host = expected.cacheHost;
    await privateWrite(stateFile, JSON.stringify(state));
    let nixConfig = env.NIX_CONFIG || '';
    if (state.github_token) {
      const scope = await jsonRequest(`${options.endpoints?.github || 'https://api.github.com'}/installation/repositories`, {
        headers: { ...apiHeaders, Authorization: `Bearer ${state.github_token}` },
      });
      if (scope?.total_count !== 1 || !Array.isArray(scope.repositories) || scope.repositories.length !== 1 || scope.repositories[0]?.full_name !== expected.repository || scope.repositories[0]?.id !== expected.repositoryId) {
        throw new Error('GitHub credential has unexpected repository scope');
      }
      nixConfig = `${nixConfig}${nixConfig && !nixConfig.endsWith('\n') ? '\n' : ''}access-tokens = github.com=${state.github_token}`;
    }
    const settingsFile = path.join(stateDirectory, 'cache-settings.json');
    await privateWrite(settingsFile, JSON.stringify(settings));
    const childEnv = {
      ...env,
      NIX_CONFIG: nixConfig,
      DASH_CACHE_SETTINGS: settingsFile,
      DASH_CACHE_ENDPOINT: settings.endpoint,
    };
    const client = fileURLToPath(new URL('./dash-cache', import.meta.url));
    const tokenFile = path.join(stateDirectory, 'cache-token');
    await privateWrite(tokenFile, `${cacheToken}\n`);
    await mkdir(cacheRoot, { recursive: true, mode: 0o700 });
    await privateWrite(path.join(cacheRoot, '.build-access-owner'), `${stateDirectory}\n`);
    await runCommand('python3', [fileURLToPath(new URL('./dash-cache.py', import.meta.url)), 'setup', '--token-file', tokenFile], childEnv, 'Private cache setup');
    await unlink(tokenFile);
    await appendWorkflow(env.GITHUB_ENV, 'DASH_CACHE_SETTINGS', settingsFile);
    await appendWorkflow(env.GITHUB_ENV, 'DASH_CACHE_ENDPOINT', settings.endpoint);
    if (state.github_token) await appendWorkflow(env.GITHUB_ENV, 'NIX_CONFIG', nixConfig);
    await appendFile(env.GITHUB_PATH, `${path.dirname(client)}\n`, { mode: 0o600 });
    for (const [name, value] of Object.entries({ 'cache-url': grant.cache_url, 'cache-expires-at': cacheExpires, 'github-expires-at': githubExpires, 'cache-client': client })) {
      await appendWorkflow(env.GITHUB_OUTPUT, name, value);
    }
    log(`Temporary ${access} access configured; cache credentials expire at ${cacheExpires}`);
    return { stateDirectory };
  } catch (error) {
    try { await cleanup({ ...env, STATE_directory: stateDirectory }, options); } catch { log('::warning::Temporary credential cleanup or revocation failed'); }
    throw error;
  }
}
