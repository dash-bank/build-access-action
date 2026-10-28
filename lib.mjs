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

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fields(value, expected) {
  return record(value) && Object.keys(value).length === expected.length && expected.every(name => Object.hasOwn(value, name));
}

function resourceMap(env, name) {
  let value;
  try { value = JSON.parse(input(env, name, '{}')); } catch { throw new Error(`Invalid ${name} configuration`); }
  if (!record(value) || Object.keys(value).some(name => !/^[A-Za-z0-9_.-]{1,100}$/.test(name) || ['.', '..'].includes(name))) throw new Error(`Invalid ${name} resource names`);
  return value;
}

function identifier(value) {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) && Number.isSafeInteger(Number(value));
}

function configuration(env) {
  const broker = origin(input(env, 'service-url'));
  const flakes = resourceMap(env, 'flakes');
  const caches = resourceMap(env, 'caches');
  const count = Object.keys(flakes).length + Object.keys(caches).length;
  if (!count || count > 16) throw new Error('Configuration requires one to sixteen resources');
  const repositories = new Set();
  for (const target of Object.values(flakes)) {
    if (!fields(target, ['repository', 'repository_id', 'owner_id']) || typeof target.repository !== 'string' || !/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(target.repository) || !identifier(target.repository_id) || !identifier(target.owner_id) || repositories.has(target.repository_id)) throw new Error('Flake configuration requires unique repository names and immutable IDs');
    repositories.add(target.repository_id);
  }
  for (const [name, cache] of Object.entries(caches)) {
    if (!fields(cache, ['url', 'public_key', 'access']) || !['read', 'read-write'].includes(cache.access)) throw new Error('Invalid cache configuration');
    let url;
    try { url = new URL(cache.url); } catch { throw new Error('Cache configuration requires HTTPS'); }
    if (!/^[A-Za-z0-9_-]+$/.test(name) || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== `/${name}` || url.href !== cache.url) throw new Error('Cache configuration requires an HTTPS URL with its registered cache name');
    const publicKey = cache.public_key;
    const encodedKey = typeof publicKey === 'string' ? publicKey.split(':')[1] : '';
    if (typeof publicKey !== 'string' || !/^[A-Za-z0-9_-]+:[A-Za-z0-9+/]{43}=$/.test(publicKey) || Buffer.from(encodedKey || '', 'base64').toString('base64') !== encodedKey) throw new Error('Cache configuration requires a valid artifact public key');
  }
  const cacheOrigins = new Set(Object.values(caches).map(cache => new URL(cache.url).origin));
  if (cacheOrigins.size > 1) throw new Error('Cache configuration requires one credential origin');
  return { broker, flakes, caches };
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
  try { return JSON.parse(await readFile(path.join(directory, 'credentials.json'), 'utf8')); }
  catch { throw new Error('Cannot read temporary credential cleanup state'); }
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
      && JSON.stringify(current?.cache_hosts) === JSON.stringify(state.cache_hosts) && current?.cache_token === state.cache_token;
  }
  if (!tokenOwnedByNewerInvocation && state.cache_token && await exists(systemNetrc)) {
    let current;
    try { current = await readFile(systemNetrc, 'utf8'); } catch (error) {
      if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error;
      current = (await runCommand('sudo', ['-n', 'cat', systemNetrc], env, 'Cache credential cleanup')).stdout;
    }
    const expected = state.cache_hosts.map(host => `machine ${host} login token password ${state.cache_token}\n`).join('');
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
  return cleanupState(directory, state, env, options);
}

async function cleanupState(directory, state, env, options) {
  let failed = false;
  for (const token of new Set(state.github_tokens || [])) {
    try {
      await jsonRequest(`${options.endpoints?.github || 'https://api.github.com'}/installation/token`, {
        method: 'DELETE', headers: { ...apiHeaders, Authorization: `Bearer ${token}` }, empty: true, acceptUnauthorized: true,
      });
    } catch { failed = true; }
  }
  try {
    if (state.cacheRoot) await removeOwnedCache(state, directory, env, options.systemNetrc || '/etc/nix/dash-cache.netrc');
  } catch { failed = true; }
  await rm(directory, { recursive: true, force: true });
  if (failed) throw new Error('Temporary credential cleanup or GitHub token revocation failed');
}

export async function run(env = process.env, options = {}) {
  const log = options.log || ((line) => process.stdout.write(`${line}\n`));
  if (env.GITHUB_ACTIONS !== 'true' || env.RUNNER_ENVIRONMENT !== 'github-hosted') throw new Error('Build access requires an ephemeral GitHub-hosted runner');
  if (!env.RUNNER_TEMP || !env.HOME || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || !env.ACTIONS_ID_TOKEN_REQUEST_URL) throw new Error('GitHub OIDC is unavailable; grant id-token: write to this job');
  const expected = configuration(env);
  const hasSources = Object.keys(expected.flakes).length > 0;
  const hasCaches = Object.keys(expected.caches).length > 0;
  const version = await runCommand('nix', ['--version'], env, 'Installed Nix check');
  let savedTokens = {}, ownedTokens = {};
  if (hasSources) {
    const match = version.stdout.match(/^nix \(Nix\) (\d+)\.(\d+)/);
    if (!match || Number(match[1]) < 2 || (Number(match[1]) === 2 && Number(match[2]) < 34)) throw new Error('Source access requires upstream Nix 2.34 or newer for repository-specific credentials');
    try { savedTokens = JSON.parse((await runCommand('nix', ['config', 'show', '--json'], env, 'Nix credential check')).stdout)['access-tokens'].value; } catch { throw new Error('Cannot verify Nix access tokens'); }
    if (!record(savedTokens) || Object.entries(savedTokens).some(([prefix, token]) => !/^[^\s=#]+$/.test(prefix) || typeof token !== 'string' || /[\s#]/.test(token))) throw new Error('Cannot safely preserve Nix access tokens');
    for (const token of new Set(Object.values(savedTokens))) if (token) mask(log, token);
    if (env.DASH_BUILD_ACCESS_SOURCE_STATE) {
      const previous = (await loadState(env.DASH_BUILD_ACCESS_SOURCE_STATE, env))?.nixTokens;
      if (record(previous)) ownedTokens = Object.fromEntries(Object.entries(savedTokens).filter(([prefix, token]) => Object.hasOwn(previous, prefix) && previous[prefix] === token));
    }
    for (const target of Object.values(expected.flakes)) {
      const prefix = `github.com/${target.repository}`;
      if (Object.hasOwn(savedTokens, prefix) && ownedTokens[prefix] !== savedTokens[prefix]) throw new Error('Refusing an existing repository credential not owned by this Action');
    }
  }
  const oidcURL = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  const fixtureOrigin = options.endpoints?.oidcOrigin;
  const githubOIDC = oidcURL.protocol === 'https:' && oidcURL.hostname.endsWith('.actions.githubusercontent.com') && !oidcURL.port && !oidcURL.username && !oidcURL.password && !oidcURL.hash;
  if (fixtureOrigin ? oidcURL.origin !== fixtureOrigin : !githubOIDC) throw new Error('Unexpected GitHub OIDC endpoint');
  oidcURL.searchParams.set('audience', expected.broker);
  const cacheRoot = hasCaches ? path.join(env.XDG_CONFIG_HOME || path.join(env.HOME, '.config'), 'dash-dev-env/cache') : undefined;
  if (hasCaches) {
    if (!path.isAbsolute(cacheRoot)) throw new Error('Cache configuration directory must be absolute');
    const renewsOwnedCache = await prepareCacheRoot(cacheRoot, env);
    if (!renewsOwnedCache && await exists(options.systemNetrc || '/etc/nix/dash-cache.netrc')) throw new Error('Refusing existing daemon cache credentials; use an ephemeral runner');
  }
  const stateDirectory = await mkdtemp(path.join(await realpath(env.RUNNER_TEMP), 'dash-build-access-'));
  await chmod(stateDirectory, 0o700);
  const stateFile = path.join(stateDirectory, 'credentials.json');
  const state = { cacheRoot, github_tokens: [] };
  await privateWrite(stateFile, JSON.stringify(state));
  await appendWorkflow(env.GITHUB_STATE, 'directory', stateDirectory);
  try {
    const identity = await jsonRequest(oidcURL, { headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
    const proof = secret(identity?.value, 'OIDC');
    mask(log, proof);
    const payload = { flakes: Object.keys(expected.flakes), caches: Object.fromEntries(Object.entries(expected.caches).map(([name, cache]) => [name, cache.access])) };
    if (env.GITHUB_EVENT_NAME === 'pull_request') payload.github_token = secret(input(env, 'github-token'), 'workflow');
    const grant = await jsonRequest(`${options.endpoints?.broker || expected.broker}/v1/exchange`, { method: 'POST', headers: { Authorization: `Bearer ${proof}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    // Capture and mask every returned source token before validating the grant,
    // including unexpected resources, so refusal can revoke all usable tokens.
    if (typeof grant?.cache_token === 'string') mask(log, grant.cache_token);
    const receivedSources = grant?.flakes && typeof grant.flakes === 'object' ? Object.values(grant.flakes) : [];
    for (const source of receivedSources) if (typeof source?.token === 'string') mask(log, source.token);
    let invalidSourceCredential = false;
    for (const source of receivedSources) if (typeof source?.token === 'string') {
      try { state.github_tokens.push(secret(source.token, 'GitHub')); }
      catch { invalidSourceCredential = true; }
    }
    // Capture the complete token set before any persistence can fail. The catch
    // path revokes from memory even when the private state file is unavailable.
    await privateWrite(stateFile, JSON.stringify(state));
    if (invalidSourceCredential) throw new Error('Invalid GitHub credential received');
    const topFields = ['flakes', 'caches', ...(hasCaches ? ['cache_token', 'cache_expires_at'] : [])];
    if (!fields(grant, topFields) || !fields(grant.flakes, Object.keys(expected.flakes)) || !fields(grant.caches, Object.keys(expected.caches))) throw new Error('Build access returned an unexpected credential response');
    const githubExpirations = [];
    state.nixTokens = { ...ownedTokens };
    for (const [name, target] of Object.entries(expected.flakes)) {
      const source = grant.flakes[name];
      if (!fields(source, ['repository', 'repository_id', 'owner_id', 'token', 'expires_at']) || source.repository !== target.repository || source.repository_id !== target.repository_id || source.owner_id !== target.owner_id) throw new Error('GitHub credential has unexpected repository scope');
      githubExpirations.push(expires(source.expires_at, 'GitHub', 3630000));
      const token = secret(source.token, 'GitHub');
      const scope = await jsonRequest(`${options.endpoints?.github || 'https://api.github.com'}/installation/repositories`, { headers: { ...apiHeaders, Authorization: `Bearer ${token}` } });
      if (scope?.total_count !== 1 || !Array.isArray(scope.repositories) || scope.repositories.length !== 1 || scope.repositories[0]?.full_name !== target.repository || scope.repositories[0]?.id !== Number(target.repository_id)) throw new Error('GitHub credential has unexpected repository scope');
      if (token.includes('#')) throw new Error('Invalid GitHub credential received');
      state.nixTokens[`github.com/${target.repository}`] = token;
    }
    let nixConfig = env.NIX_CONFIG || '';
    if (hasSources) {
      // Nix's extra-access-tokens keeps the first value for duplicate prefixes.
      // Append the complete effective map so renewal replaces owned prefixes.
      nixConfig += `${nixConfig && !nixConfig.endsWith('\n') ? '\n' : ''}access-tokens = ${Object.entries({ ...savedTokens, ...state.nixTokens }).map(([prefix, token]) => `${prefix}=${token}`).join(' ')}`;
    }
    let cacheExpires = '';
    const client = fileURLToPath(new URL('./dash-cache', import.meta.url));
    if (hasCaches) {
      state.cache_token = secret(grant.cache_token, 'cache');
      cacheExpires = expires(grant.cache_expires_at, 'cache', 1830000);
      const settings = { caches: Object.create(null) };
      const hosts = new Set();
      for (const [name, cache] of Object.entries(expected.caches)) {
        const actual = grant.caches[name];
        if (!fields(actual, ['url', 'public_key', 'access']) || actual.url !== cache.url || actual.public_key !== cache.public_key || actual.access !== cache.access) throw new Error('Build access returned an unexpected cache identity or permission');
        const url = new URL(cache.url);
        settings.caches[name] = { endpoint: url.origin, cache: name, public_key: cache.public_key };
        hosts.add(url.hostname.replace(/^\[|\]$/g, ''));
      }
      state.cache_hosts = [...hosts].sort();
      await privateWrite(stateFile, JSON.stringify(state));
      const settingsFile = path.join(stateDirectory, 'cache-settings.json');
      await privateWrite(settingsFile, JSON.stringify(settings));
      const tokenFile = path.join(stateDirectory, 'cache-token');
      await privateWrite(tokenFile, `${state.cache_token}\n`);
      await mkdir(cacheRoot, { recursive: true, mode: 0o700 });
      await privateWrite(path.join(cacheRoot, '.build-access-owner'), `${stateDirectory}\n`);
      const childEnv = { ...env, NIX_CONFIG: nixConfig, DASH_CACHE_SETTINGS: settingsFile };
      delete childEnv.DASH_CACHE_ENDPOINT;
      await runCommand('python3', [fileURLToPath(new URL('./dash-cache.py', import.meta.url)), 'setup', '--token-file', tokenFile], childEnv, 'Private cache setup');
      await unlink(tokenFile);
      await appendWorkflow(env.GITHUB_ENV, 'DASH_CACHE_SETTINGS', settingsFile);
      await appendFile(env.GITHUB_PATH, `${path.dirname(client)}\n`, { mode: 0o600 });
    }
    await privateWrite(stateFile, JSON.stringify(state));
    if (hasSources) {
      await appendWorkflow(env.GITHUB_ENV, 'NIX_CONFIG', nixConfig);
      await appendWorkflow(env.GITHUB_ENV, 'DASH_BUILD_ACCESS_SOURCE_STATE', stateDirectory);
    }
    for (const [name, value] of Object.entries({ 'cache-urls': Object.values(expected.caches).map(cache => cache.url).join('\n'), 'cache-expires-at': cacheExpires, 'github-expires-at': githubExpirations.sort()[0] || '', 'cache-client': hasCaches ? client : '' })) await appendWorkflow(env.GITHUB_OUTPUT, name, value);
    log(`Temporary access configured for ${Object.keys(expected.flakes).length} source(s) and ${Object.keys(expected.caches).length} cache(s)`);
    return { stateDirectory };
  } catch (error) {
    try { await cleanupState(stateDirectory, state, env, options); } catch { log('::warning::Temporary credential cleanup or revocation failed'); }
    throw error;
  }
}
