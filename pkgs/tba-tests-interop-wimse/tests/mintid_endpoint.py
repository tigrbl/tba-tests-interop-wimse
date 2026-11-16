"""Use the MintID verifier at the final policy hop before writing an effect."""

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess

from tba_tests_interop_wimse.http_fixture import call_resource

from support.typed_service_bindings import TypedServiceBindings
from support.wpt_fixture import WptFixture


OPERATION = "mintid-check"
BRIDGE = Path(__file__).with_name("mintid_bridge.py")
RUNTIME_BRIDGE = "/tbafixture/mintid_bridge.py"
DECISION_TIMEOUT = 480
HOSTED_SERVICES = ("idchaind", "issuer-agent", "verifier", "selfrevoke-relay")
REVOCATIONS = {
    "issuer-revocation-refused": "issuer",
    "holder-self-revocation-refused": "kill_switch",
}


def driver_fingerprint(container):
    def docker(*args):
        return subprocess.run(
            ["docker", *args], text=True, capture_output=True, timeout=20, check=True,
        ).stdout.strip()

    image = docker("inspect", "--format", "{{.Image}}", container)
    mounted = docker("exec", container, "sha256sum", RUNTIME_BRIDGE).split()[0]
    digest = sha256(BRIDGE.read_bytes()).hexdigest()
    if mounted != digest:
        raise ValueError("MintID driver bridge differs from the local test source")
    return {"driver_image": image, "bridge_sha256": digest}


def hosted_service_images():
    names = [f"tba-interop-mintid-{service}-1" for service in HOSTED_SERVICES]
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}} {{.Image}}", *names],
        text=True, capture_output=True, timeout=20, check=True,
    )
    images = {}
    for service, record in zip(HOSTED_SERVICES, result.stdout.splitlines(), strict=True):
        running, image = record.split()
        if running != "true":
            raise ValueError(f"MintID {service} is not running")
        images[service] = image
    return images


def validate_decision(result, path, actor):
    if not result.get("session_id") or result.get("actor") != actor:
        raise ValueError("MintID trace omitted the verifier session or workload mapping")
    if not path:
        if result.get("accepted") is not True or result.get("witness_refresh_usable") is not True:
            raise ValueError("MintID verifier refused the active credential or its refreshed witness")
        return
    if (result.get("revocation_path") != path or result.get("accepted") is not False
            or result.get("refusal_confirmed") is not True or result.get("witness_refresh_refused") is not True
            or not result.get("baseline_session_id") or not result.get("carrying_root")):
        raise ValueError("MintID verifier did not confirm the requested revocation")


def mintid_decision(container, path, actor):
    try:
        reply = subprocess.run(
            ["docker", "exec", "-i", container, "python", RUNTIME_BRIDGE],
            input=json.dumps({"path": path, "actor": actor}), text=True, encoding="utf-8",
            capture_output=True, timeout=DECISION_TIMEOUT, check=True,
        )
    except subprocess.CalledProcessError as error:
        detail = next((line for line in reversed(error.stderr.splitlines()) if line.strip()), "no diagnostic")
        raise ValueError(f"MintID trace did not produce an attributable decision ({detail})") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError("MintID trace exceeded its runtime budget") from error
    result = json.loads(reply.stdout)
    validate_decision(result, path, actor)
    return result


def mintid_caller(caller):
    def request(host, port, dns, *, readback=False, headers=None):
        connection = caller.connection(host, port, dns)
        try:
            connection.connect()
            connection.sock.settimeout(DECISION_TIMEOUT + 30)
            return call_resource(connection, readback=readback, headers=headers)
        finally:
            connection.close()

    return SimpleNamespace(request=request, connection=caller.connection, present=getattr(caller, "present", None))


@contextmanager
def mintid_wic_running(running, **policies):
    with running(**policies) as (caller, receiver):
        yield mintid_caller(caller), receiver


class MintIDBindings(TypedServiceBindings):
    bindings = {**TypedServiceBindings.bindings, OPERATION: {"mintid"}}
    write_gates = {OPERATION}

    def configure_lab(self, lab):
        @contextmanager
        def hop(*args, **kwargs):
            with lab.hop(*args, **kwargs) as fixture:
                if isinstance(fixture, WptFixture):
                    caller, combined_caller = fixture.caller, fixture.combined_caller
                    fixture.caller = lambda variant: mintid_caller(caller(variant))
                    fixture.combined_caller = lambda application: mintid_caller(combined_caller(application))
                else:
                    running = fixture.running
                    fixture.running = lambda **policies: mintid_wic_running(running, **policies)
                yield fixture

        return SimpleNamespace(hop=hop)

    def support_request(self, index, fault):
        if self.hops[index]["operation"] != OPERATION:
            return super().support_request(index, fault)
        path = REVOCATIONS[fault] if fault else ""
        actor = self.hops[index]["caller"]
        result = mintid_decision(self.agent_factory(), path, actor)
        if path:
            return {**self.refusal(fault), "mintid_verifier": result}
        return self.accepted("current-non-revocation-proof-accepted", mintid_verifier=result)
