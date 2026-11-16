const fixture = JSON.parse(Deno.readTextFileSync("/tmp/example.json"));
const root = "/tmp/tba-workflow/agents/test/";
for (const [name, contents] of Object.entries(fixture.agent_relative_files)) {
  const path = root + name;
  Deno.mkdirSync(path.substring(0, path.lastIndexOf("/")), {recursive: true});
  Deno.writeTextFileSync(path, JSON.stringify(contents, null, 2));
}
const workflow = structuredClone(fixture.agent_relative_files["workflows/text-stats.json"]);
workflow.workflow_id = "interop-outbound";
workflow.title = "WIMSE outbound interop control";
workflow.input_schema = {
  type: "object",
  required: ["mode"],
  properties: {
    mode: {type: "string", enum: ["wpt", "http-sig"]},
    resource: {type: "string", enum: ["writes", "effects", "policy"], default: "writes"},
    context: {type: "object", additionalProperties: {type: "string"}, default: {}},
  },
  additionalProperties: false,
};
workflow.actions[0].code =
  "const {wimseFetch} = await import('./tools/nats_bridge.ts'); " +
  "const mode = {{ json .mode }}; " +
  "const resource = {{ json .resource }} || 'writes'; " +
  "const headers = {{ json .context }} || {}; " +
  "const response = await wimseFetch('https://127.0.0.1:15001/' + resource, " +
  "{mode, method: resource === 'effects' ? 'GET' : 'POST', headers}); " +
  "return {status:response.status, outcome:await response.json()};";
workflow.output = {status: "{{ stats.status }}", outcome: "{{ stats.outcome }}"};
Deno.writeTextFileSync(root + "workflows/interop-outbound.json", JSON.stringify(workflow, null, 2));

const ungranted = structuredClone(fixture.agent_relative_files["workflows/text-stats.json"]);
ungranted.workflow_id = "interop-ungranted";
ungranted.title = "WIMSE scope refusal control";
Deno.writeTextFileSync(root + "workflows/interop-ungranted.json", JSON.stringify(ungranted, null, 2));

const policy = structuredClone(workflow);
policy.workflow_id = "interop-policy";
policy.title = "Authorized WIMSE workflow policy gate";
policy.input_schema.required = ["mode", "context"];
policy.actions[0].code =
  "const {wimseFetch} = await import('./tools/nats_bridge.ts'); " +
  "const mode = {{ json .mode }}; const context = {{ json .context }}; " +
  "const response = await wimseFetch('https://127.0.0.1:15001/policy', " +
  "{mode, method:'POST', headers:context}); " +
  "return {status:response.status, outcome:await response.json()};";
Deno.writeTextFileSync(root + "workflows/interop-policy.json", JSON.stringify(policy, null, 2));

const sequence = structuredClone(workflow);
sequence.workflow_id = "interop-policy-sequence";
sequence.title = "Preflight and protected commit within one workflow execution";
sequence.actions[0].code =
  "const {wimseFetch} = await import('./tools/nats_bridge.ts'); " +
  "const mode = {{ json .mode }}; const headers = {{ json .context }} || {}; " +
  "const base = 'https://127.0.0.1:15001'; " +
  "const preflight = await wimseFetch(base + '/effects', {mode, method:'GET', headers}); " +
  "if (!preflight.ok) return {status:preflight.status, outcome:await preflight.json()}; " +
  "const commit = await wimseFetch(base + '/writes', {mode, method:'POST', headers}); " +
  "return {status:commit.status, outcome:await commit.json()};";
Deno.writeTextFileSync(root + "workflows/interop-policy-sequence.json", JSON.stringify(sequence, null, 2));
