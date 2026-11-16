import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join } from 'node:path';

const [, , checkout, output] = process.argv;
const identity = join(checkout, 'packages/server/src/identity');
writeFileSync(join(output, 'package.json'), '{"type":"module"}');
for (const name of ['types', 'wimse', 'http-signature', 'structured-fields', 'txn-token']) {
  const source = readFileSync(join(identity, name + '.ts'), 'utf8');
  const compiled = stripTypeScriptTypes(source, { mode: 'transform' });
  writeFileSync(join(output, name + '.js'), compiled);
}

const demo = join(checkout, 'scripts/hackathon/lib');
const client = readFileSync(join(demo, 'client.mjs'), 'utf8').replaceAll('\r\n', '\n');
const selection = '  return {\n    /** WIT + WPT';
if (client.split(selection).length !== 2) {
  throw new Error('Cannot expose the pinned Cred WPT constructor');
}
// Add an export on the returned object so the pinned WPT constructor can
// target the fixture File Tool instead of Cred's hard-coded /api/v1/delegate.
writeFileSync(join(output, 'nine_hop_cred_client.mjs'),
  client.replace(selection, '  return {\n    wpt,\n    /** WIT + WPT'));
copyFileSync(join(demo, 'issuers.mjs'), join(output, 'issuers.mjs'));
copyFileSync(new URL('./nine_hop_cred.mjs', import.meta.url), join(output, 'nine_hop_cred.mjs'));
