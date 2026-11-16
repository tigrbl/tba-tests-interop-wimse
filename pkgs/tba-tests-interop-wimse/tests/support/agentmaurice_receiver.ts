const reader = Deno.stdin.readable.pipeThrough(new TextDecoderStream()).getReader();
const abort = new AbortController();
const waiting = new Map<string, (value: {status: number; body?: unknown}) => void>();

async function decisions() {
  let pending = "";
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    pending += chunk.value;
    let newline;
    while ((newline = pending.indexOf("\n")) >= 0) {
      const result = JSON.parse(pending.slice(0, newline));
      pending = pending.slice(newline + 1);
      const id = result.request_id ?? (waiting.size === 1 ? waiting.keys().next().value : undefined);
      const respond = waiting.get(id);
      if (!respond) throw new Error("No matching request for the verification result");
      waiting.delete(id);
      respond(result);
    }
  }
}
decisions().finally(() => {
  for (const respond of waiting.values()) respond({status: 503});
  waiting.clear();
  abort.abort();
});

Deno.serve({
  signal: abort.signal,
  hostname: "127.0.0.1",
  port: 15001,
  cert: Deno.readTextFileSync("/tmp/receiver-cert.pem"),
  key: Deno.readTextFileSync("/tmp/receiver-key.pem"),
  onListen() { console.log(JSON.stringify({ready: true})); },
}, async (request, info) => {
  const url = new URL(request.url);
  const id = crypto.randomUUID();
  const packet = {
    request_id: id, url: request.url, path: url.pathname + url.search, method: request.method,
    headers: Object.fromEntries(request.headers), body: await request.text(), peer: info.remoteAddr,
  };
  const {status, body} = await new Promise<{status: number; body?: unknown}>(resolve => {
    waiting.set(id, resolve);
    console.log(JSON.stringify(packet));
  });
  return Response.json(body ?? {status}, {status});
});
