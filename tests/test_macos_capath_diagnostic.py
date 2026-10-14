import os
import ssl
import tempfile
from collections import Counter

import pytest
import urllib3
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL.crypto import X509

import truststore

results: list[tuple[bool, bool]] = []


@pytest.fixture(scope="module", autouse=True)
def report_results():
    yield
    print(f"capath diagnostic summary: {Counter(results)}", flush=True)


@pytest.mark.parametrize("attempt", range(20))
def test_capath_anchor_visibility(attempt, trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca_der = trustme_ca._certificate.public_bytes(Encoding.DER)

    with tempfile.TemporaryDirectory() as capath:
        cert_path = f"{capath}/cert.pem"
        with open(cert_path, "wb") as certfile:
            certfile.write(trustme_ca.cert_pem.bytes())
        cert_hash = X509.from_cryptography(trustme_ca._certificate).subject_name_hash()
        os.symlink(cert_path, f"{capath}/{cert_hash:x}.0")

        ctx.load_verify_locations(capath=capath)
        ca_visible = ca_der in ctx._ctx.get_ca_certs(binary_form=True)

        httpserver.expect_request("/", method="GET").respond_with_json({})
        request_succeeded = False
        error = None
        try:
            with urllib3.PoolManager(ssl_context=ctx, retries=False) as http:
                http.request("GET", httpserver.url_for("/"))
            request_succeeded = True
        except urllib3.exceptions.HTTPError as exc:
            error = repr(exc)

    results.append((ca_visible, request_succeeded))
    print(
        f"attempt={attempt} ca_visible={ca_visible} "
        f"request_succeeded={request_succeeded} error={error}",
        flush=True,
    )
