const input = JSON.parse(await new Response(Deno.stdin.readable).text());
const url = new URL(input.path, "http://127.0.0.1:5000");
if (url.origin !== "http://127.0.0.1:5000") throw new Error("non-loopback workflow target");
const response = await fetch(url, {method: "POST", headers: input.headers, body: input.body});
const content = await response.json();
const execution = content.execution ?? content;
console.log(JSON.stringify({
  status: response.status,
  execution_id: execution.execution_id ?? execution.id,
  state: execution.state,
  data: execution.data,
  error: content.error,
}));
