import { createPublicKey } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

if (process.argv[2] === 'build') {
  const checkout = process.argv[3];
  const ts = (await import(pathToFileURL(join(checkout, 'node_modules/typescript/lib/typescript.js')))).default;
  const source = readFileSync(join(checkout, 'packages/server/src/identity/txn-token.ts'), 'utf8');
  const result = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  if (result.diagnostics.some(item => item.category === ts.DiagnosticCategory.Error)) {
    throw new Error('Unable to compile the pinned Cred transaction-token verifier');
  }
  writeFileSync(new URL('./txn-token.js', import.meta.url), result.outputText);
} else {
  const { verifyTxnToken, mappedProviderScopes, TxnTokenRefusal } = await import('./txn-token.js');
  const { token, jwks, audience, scopeMap } = JSON.parse(readFileSync(0, 'utf8'));
  const trust = {
    aud: audience,
    keys: new Map(jwks.map(jwk => [jwk.kid, { key: createPublicKey({ key: jwk, format: 'jwk' }), alg: jwk.alg }])),
    scopeMap: { matrix: scopeMap },
    clockSkewSec: 0,
  };
  try {
    const verified = verifyTxnToken(token, trust);
    const operations = mappedProviderScopes(trust, 'matrix', verified.scopes);
    console.log(JSON.stringify({ claims: verified.claims, operations }));
  } catch (error) {
    if (!(error instanceof TxnTokenRefusal)) throw error;
    console.log(JSON.stringify({ denied: error.code }));
  }
}
