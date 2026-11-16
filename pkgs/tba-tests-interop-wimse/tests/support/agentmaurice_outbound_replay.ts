const request = JSON.parse(await new Response(Deno.stdin.readable).text());
const url = "https://127.0.0.1:15001/writes";
if (request.url !== url || request.method !== "POST" || request.body) {
  throw new Error("Expected the disposable receiver's bodyless loopback POST");
}
const target = request.rewrite_path === true ? "https://127.0.0.1:15001/rewritten" : url;
const client = Deno.createHttpClient({caCerts: [Deno.readTextFileSync("/tmp/receiver-ca.pem")]});
try {
  const headers = new Headers(request.headers);
  for (const name of ["connection", "host", "content-length", "transfer-encoding"]) headers.delete(name);
  const response = await fetch(target, {method: "POST", headers, redirect: "error", client});
  await response.body?.cancel();
  console.log(JSON.stringify(response.status));
} finally {
  client.close();
}
