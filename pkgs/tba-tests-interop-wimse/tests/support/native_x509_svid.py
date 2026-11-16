"""Mint short-lived native X.509-SVID credentials for the loopback lab."""

from cryptography.hazmat.primitives import serialization
from tba_concrete_x509_svid_credential import X509SvidCredential
from tba_testkit_workload_credential_conformance.fixtures import _certificate

from support.wic_fixture import write_leaf


class NativeX509SvidIssuer:
    def __init__(self):
        self.authority = _certificate(())

    def mint(self, identity):
        leaf = _certificate((identity,), issuer=self.authority)
        chain = (leaf[0].public_bytes(serialization.Encoding.DER),
                 self.authority[0].public_bytes(serialization.Encoding.DER))
        X509SvidCredential(identity, chain)
        return leaf

    def issue_pair(self, directory, subjects, receiver):
        anchor = directory / "tba-svid-bundle.pem"
        root = self.authority[0].public_bytes(serialization.Encoding.PEM)
        anchor.write_bytes(root)
        server = write_leaf(directory, "server-svid", self.mint(receiver), anchor)
        if len(subjects) == 1 and subjects[0].startswith("spiffe://example.org/"):
            caller = self.mint(subjects[0])
        else:
            # Hand the verifier a malformed or foreign URI over valid mTLS.
            # Construct this test leaf directly, bypassing SVID issuance validation.
            caller = _certificate(subjects, issuer=self.authority)
        return write_leaf(directory, "client-svid", caller, anchor), server
