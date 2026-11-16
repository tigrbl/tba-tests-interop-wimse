"""Bind Teleport's acquired X.509-SVID to each qualified workload profile."""

from contextlib import contextmanager
from copy import copy

from support.teleport_endpoint import ISSUER, TeleportBindings
from support.wpt_fixture import WptFixture


class TeleportWorkloadLab:
    def __init__(self, lab, issuer):
        self.lab = copy(lab)
        self.lab.issuer = issuer
        if getattr(self.lab, "fallback", None) is not None:
            self.lab.fallback = copy(self.lab.fallback)
            self.lab.fallback.issuer = issuer

    @contextmanager
    def hop(self, case, direction, hop, names):
        with self.lab.hop(case, direction, hop, names) as fixture:
            if hop["wic_issuer"] == ISSUER and isinstance(fixture, WptFixture):
                # The service flow records the DER leaf at the receiver's TLS verifier.
                fixture.receiver_verifier = fixture.wic.receiver_verifier
            yield fixture


class CombinedTeleportBindings(TeleportBindings):
    def configure_lab(self, lab):
        self.acquired_issuer.issuer = lab.issuer
        return TeleportWorkloadLab(lab, self.acquired_issuer)
