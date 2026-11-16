import { createPrivateKey, createPublicKey } from 'node:crypto';
import { createInterface } from 'node:readline';
import { signWimseRequest, verifyWimseRequestSignature } from './http-signature.js';
import { IdentityRefusal } from './types.js';
import { TxnTokenRefusal, verifyTxnToken } from './txn-token.js';
import { keyFitsAlg, sigAlg, verifySignature, verifyWit, verifyWpt } from './wimse.js';
import { agentClient } from './nine_hop_cred_client.mjs';

function anchors(keys) {
  return new Map(keys.map(jwk => [jwk.kid, {
    key: createPublicKey({ key: jwk, format: 'jwk' }),
    alg: jwk.alg,
  }]));
}

function verifyAccessToken(input, config) {
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input.token)) {
    return { denied: 'access-token-malformed' };
  }
  const [header, payload, signature] = input.token.split('.');
  const decode = segment => JSON.parse(Buffer.from(segment, 'base64url'));
  const jose = decode(header);
  const alg = sigAlg(jose.alg);
  const anchor = config.keys.get(jose.kid);
  if (jose.typ !== 'at+jwt' || jose.crit !== undefined || !anchor || !alg ||
      (anchor.alg !== undefined && sigAlg(anchor.alg) !== alg) || !keyFitsAlg(anchor.key, alg) ||
      !verifySignature(alg, anchor.key, Buffer.from(header + '.' + payload), Buffer.from(signature, 'base64url'))) {
    return { denied: 'access-token-signature-or-type' };
  }
  const claims = decode(payload);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(input.audience) || !Number.isFinite(claims.exp) ||
      !Number.isFinite(claims.iat) || !(claims.iat <= input.now && input.now < claims.exp) ||
      !['txn', 'sub', 'scope'].every(name => typeof claims[name] === 'string' && claims[name])) {
    return { denied: 'access-token-claims' };
  }
  return { claims };
}

function dispatch(input) {
  const config = { now: () => input.now, clockSkewSec: 0 };
  switch (input.command) {
    case 'http-sign':
      return { headers: signWimseRequest({
        ...input.request,
        body: Buffer.from(input.request.body, 'base64'),
        audience: input.audience,
        privateKey: createPrivateKey({ key: input.key, format: 'jwk' }),
        alg: input.key.alg,
        wit: input.wit,
      }) };
    case 'wpt-sign': {
      const workload = { wit: input.wit, privateKey: createPrivateKey({ key: input.key, format: 'jwk' }) };
      const client = agentClient({ baseUrl: input.audience, workload });
      return { proof: client.wpt('', input.transaction) };
    }
    case 'http-verify':
    case 'wpt-verify': {
      config.trustDomains = Object.fromEntries(Object.entries(input.trust).map(
        ([domain, keys]) => [domain, anchors(keys)],
      ));
      const request = input.request;
      if (input.command === 'http-verify') {
        const result = verifyWimseRequestSignature(
          { ...request, body: Buffer.from(request.body, 'base64') },
          { ...config, audiences: [input.audience] },
        );
        if (!result) return { denied: 'missing-wimse-signature' };
        return { subject: result.wit.subject, witClaims: result.wit.claims, nonce: result.nonce, expires: result.expires };
      }
      const wit = verifyWit(request.headers['workload-identity-token'], config);
      const result = verifyWpt(input.proof, wit, { headers: request.headers, targetUri: input.audience }, config);
      return { subject: wit.subject, witClaims: wit.claims, nonce: result.jti, expires: result.exp };
    }
    case 'transaction-verify':
      return { claims: verifyTxnToken(input.token, {
        ...config, aud: input.audience, keys: anchors(input.keys), scopeMap: {},
      }).claims };
    case 'access-verify':
      return verifyAccessToken(input, { keys: anchors(input.keys) });
    default:
      throw new Error('Unknown Cred nine-hop operation');
  }
}

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  let result;
  try {
    result = dispatch(JSON.parse(line));
  } catch (error) {
    result = error instanceof IdentityRefusal || error instanceof TxnTokenRefusal
      ? { denied: error.code }
      : { error: error.name };
  }
  process.stdout.write(JSON.stringify(result) + '\n');
}
