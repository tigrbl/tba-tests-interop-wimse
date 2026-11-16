import { Agent, request } from "node:http";

const agent = new Agent({keepAlive: true, maxSockets: 1});
const input = Deno.stdin.readable.pipeThrough(new TextDecoderStream()).getReader();
let pending = "";
async function call(payload: { path: string; body: string; headers: Record<string, string> }) {
  const url = new URL(payload.path, "http://127.0.0.1:5000");
  if (url.origin !== "http://127.0.0.1:5000") throw new Error("non-loopback workflow target");
  return await new Promise((resolve, reject) => {
    const req = request(url, {
      agent, method: "POST",
      headers: {...payload.headers, "content-length": Buffer.byteLength(payload.body)},
    }, response => {
      let body = "";
      const connection = {port: response.socket.localPort, reused: req.reusedSocket};
      response.setEncoding("utf8");
      response.on("data", chunk => { body += chunk; });
      response.on("end", () => {
        try {
          const raw = JSON.parse(body);
          const execution = raw.execution ?? raw;
          resolve({status: response.statusCode, state: execution.state, data: execution.data, connection});
        } catch (error) {
          reject(error);
        }
      });
      response.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(30000, () => req.destroy(new Error("workflow session timed out")));
    req.end(payload.body);
  });
}
try {
  while (true) {
    const {value, done} = await input.read();
    if (done) break;
    pending += value;
    let newline;
    while ((newline = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      console.log(JSON.stringify(await call(JSON.parse(line))));
    }
  }
} finally {
  agent.destroy();
}
