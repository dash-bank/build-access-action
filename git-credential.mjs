// Git invokes this helper with an operation after its pinned state/repository
// arguments. The only output is a credential for one exact approved source.
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

async function credential() {
  const [directory, repository, operation] = process.argv.slice(2);
  if (operation !== 'get' || process.argv.length !== 5 || !/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(repository || '')) return;
  let bytes = 0, input = '';
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > 16384) return;
    input += chunk.toString('utf8');
  }
  if (/[\r\0]/.test(input) || !input.endsWith('\n')) return;
  const request = Object.create(null);
  for (const line of input.slice(0, input.endsWith('\n\n') ? -2 : -1).split('\n')) {
    const separator = line.indexOf('=');
    if (separator < 1) return;
    const name = line.slice(0, separator), value = line.slice(separator + 1);
    // Git sends repeatable capability/challenge metadata during HTTP auth.
    // It carries no repository authority; only binding fields below select it.
    if (['capability[]', 'wwwauth[]'].includes(name)) continue;
    if (!['protocol', 'host', 'path', 'username'].includes(name) || Object.hasOwn(request, name)) return;
    request[name] = value;
  }
  if (request.protocol !== 'https' || request.host !== 'github.com' || ![repository, `${repository}.git`, `${repository}/`, `${repository}.git/`].includes(request.path) || (request.username !== undefined && request.username !== 'x-access-token')) return;
  if (!process.env.RUNNER_TEMP || !path.isAbsolute(directory) || !path.basename(directory).startsWith('dash-build-access-')) return;
  const temp = await realpath(process.env.RUNNER_TEMP);
  if (path.dirname(directory) !== temp || await realpath(directory) !== directory) return;
  const info = await lstat(directory);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) return;
  const file = await open(path.join(directory, 'credentials.json'), constants.O_RDONLY | constants.O_NOFOLLOW);
  let state;
  try {
    const info = await file.stat();
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o600 || info.nlink !== 1 || info.size > 1048576) return;
    state = JSON.parse(await file.readFile('utf8'));
  } finally { await file.close(); }
  const source = state?.gitSources?.[repository];
  const token = state?.nixTokens?.[`github.com/${repository}`];
  if (source?.directory !== directory || !Number.isFinite(Date.parse(source.expires_at)) || Date.parse(source.expires_at) <= Date.now() || typeof token !== 'string' || !token || token.length > 16384 || /[\s#]/.test(token) || !Array.isArray(state?.github_tokens) || !state.github_tokens.includes(token)) return;
  process.stdout.write(`username=x-access-token\npassword=${token}\n\n`);
}

// Malformed requests, missing/revoked state and storage operations fail closed.
try { await credential(); } catch { /* Never reflect credential bytes or paths. */ }
