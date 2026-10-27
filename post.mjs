import { cleanup } from './lib.mjs';

try {
  await cleanup(process.env);
} catch (error) {
  process.stdout.write(`::error::${String(error.message).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A')}\n`);
  process.exitCode = 1;
}
