"""Exercise Cofide B_CHAIN proof bindings over a disposable loopback socket."""
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("bridge", type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.upstream.resolve() / "peers"))
    import wimse
    from nine_hop_cofide import DRIVER_SUBJECT, Driver, Proof

    authority = wimse.new_workload_key()
    workload = wimse.new_workload_key()
    anchor = wimse.jwk_from_public(authority.public_key(), kid="peer-1")
    trust = {"peer.ietf127.example": {"keys": [anchor]}}
    witness = wimse.issue_wit(
        authority, kid="peer-1", iss="http://peer.ietf127.example", sub=DRIVER_SUBJECT,
        workload_pub_jwk=wimse.jwk_from_public(workload.public_key()),
    )
    next_workload = wimse.new_workload_key()
    next_witness = wimse.issue_wit(
        authority, kid="peer-1", iss="http://peer.ietf127.example", sub=DRIVER_SUBJECT,
        workload_pub_jwk=wimse.jwk_from_public(next_workload.public_key()),
    )
    proof = Proof(wimse, args.bridge)
    driver = Driver(proof)
    audiences = {
        "/workflows/text-stats/executions": "http://maurice.ietf127.example:5050",
        "/oauth/token": "http://maurice.ietf127.example:5051",
        "/coordinate": "http://rich.ietf127.example:5060",
        "/research": "http://rich.ietf127.example:5062",
    }
    observations = []

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            headers = dict(self.headers)
            expected_aud = audiences[self.path]
            result = proof.verify_wimse_proof("POST", self.path, headers, body, trust, expected_aud=expected_aud)
            reference = wimse.verify_wimse_proof("POST", self.path, headers, body, trust, expected_aud=expected_aud)
            observations.append((self.path, result[1], result[2], reference[1], reference[2]))
            payload = json.dumps({"status": result[2]}).encode()
            self.send_response(result[1])
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Receiver) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            for path, body, headers in (
                ("/workflows/text-stats/executions", b'{"inputs":{"text":"hello wimse"}}', {"Txn-Token": "fixture-A"}),
                ("/oauth/token", b'{"subject_token":"fixture-A"}', {}),
                ("/coordinate", b'{"file":"Q3.pdf"}', {"Authorization": "Bearer fixture-B"}),
            ):
                request = driver.http_sig(
                    "POST", url + path, body, witness if not observations else next_witness,
                    workload if not observations else next_workload, aud=audiences[path], headers=headers,
                )
                assert request.headers["workload-identity-token"] == witness
                response = wimse.send(request, case="B_CHAIN")
                assert response.status == 200, (path, response.body)
            for signer, path, headers in (
                (wimse.http_sig, "/workflows/text-stats/executions", {"Txn-Token": "fixture-A"}),
                (wimse.http_sig, "/coordinate", {"Authorization": "Bearer fixture-B"}),
                (proof.http_sig, "/research", {"Txn-Token": "fixture-B1"}),
            ):
                response = wimse.send(signer(
                    "POST", url + path, b'{"file":"Q3.pdf"}', witness, workload,
                    aud=audiences[path], headers=headers,
                ), case="B_CHAIN")
                assert response.status == 200, (path, response.body)
        finally:
            server.shutdown()
            thread.join()
    assert [item[1] for item in observations] == [200] * 6
    assert [item[3] for item in observations] == [400, 400, 400, 200, 200, 400]
    for path, status, reason, reference_status, reference_reason in observations:
        print(f"{path}: Cofide verifier {status} {reason}; unchanged reference verifier {reference_status} {reference_reason}")


if __name__ == "__main__":
    main()
