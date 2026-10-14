import os
import platform
import ssl
import tempfile
from collections import Counter

import pytest
import trustme
import urllib3
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL.crypto import X509

results: list[tuple[bool, bool, bool]] = []


@pytest.fixture
def trustme_ca():
    return trustme.CA()


@pytest.fixture(scope="module", autouse=True)
def report_results():
    yield
    print(f"capath diagnostic summary: {Counter(results)}", flush=True)


@pytest.mark.parametrize("attempt", range(50))
def test_capath_anchor_visibility(attempt, trustme_ca, httpserver):
    import truststore

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca_der = trustme_ca._certificate.public_bytes(Encoding.DER)

    with tempfile.TemporaryDirectory() as capath:
        cert_path = f"{capath}/cert.pem"
        with open(cert_path, "wb") as certfile:
            certfile.write(trustme_ca.cert_pem.bytes())
        cert_hash = X509.from_cryptography(trustme_ca._certificate).subject_name_hash()
        os.symlink(cert_path, f"{capath}/{cert_hash:x}.0")

        ctx.load_verify_locations(capath=capath)
        ca_visible_before = ca_der in ctx._ctx.get_ca_certs(binary_form=True)

        httpserver.expect_request("/", method="GET").respond_with_json({})
        request_succeeded = False
        error = None
        macos = None
        modern_api = None
        if platform.system() == "Darwin":
            import truststore._macos as macos

            modern_api = macos._is_macos_version_10_14_or_later
            macos._is_macos_version_10_14_or_later = False
        try:
            with urllib3.PoolManager(ssl_context=ctx, retries=False) as http:
                http.request("GET", httpserver.url_for("/"))
            request_succeeded = True
        except urllib3.exceptions.HTTPError as exc:
            error = repr(exc)
        finally:
            if macos is not None:
                macos._is_macos_version_10_14_or_later = modern_api

        ca_visible_after = ca_der in ctx._ctx.get_ca_certs(binary_form=True)

    results.append((ca_visible_before, ca_visible_after, request_succeeded))
    print(
        f"attempt={attempt} ca_visible_before={ca_visible_before} "
        f"ca_visible_after={ca_visible_after} "
        f"request_succeeded={request_succeeded} error={error}",
        flush=True,
    )
