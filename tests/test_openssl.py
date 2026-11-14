import ssl
import sys
from pathlib import Path

import pytest
import trustme
import urllib3
from OpenSSL import crypto
from pytest_httpserver import HTTPServer

import truststore
from tests.conftest import NETWORK_TIMEOUT
from truststore import _openssl

pytestmark = pytest.mark.skipif(
    sys.platform in ("win32", "darwin"), reason="Requires the OpenSSL backend"
)


def _ca_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: trustme.CA,
    suffix: str,
    fallback_authority: trustme.CA,
) -> Path:
    """Configure real environment paths without changing the OS trust store."""
    certificate = crypto.load_certificate(
        crypto.FILETYPE_PEM, authority.cert_pem.bytes()
    )
    filename = f"{certificate.subject_name_hash():08x}.{suffix}"
    directory = tmp_path / "certs"
    directory.mkdir()
    authority.cert_pem.write_to_path(directory / filename)
    fallback_file = tmp_path / "fallback.pem"
    fallback_authority.cert_pem.write_to_path(fallback_file)

    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(directory))
    monkeypatch.setattr(_openssl, "_CA_FILE_CANDIDATES", [str(fallback_file)])
    return fallback_file


def _request(httpserver: HTTPServer) -> None:
    """Verify a real HTTPS response through the public context."""
    httpserver.expect_request("/").respond_with_data("ok")
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with urllib3.PoolManager(ssl_context=context) as client:
        response = client.request(
            "GET", httpserver.url_for("/"), retries=False, timeout=NETWORK_TIMEOUT
        )
    assert response.status == 200
    assert response.data == b"ok"


@pytest.mark.parametrize("suffix", ["0\n", "\N{ARABIC-INDIC DIGIT ZERO}"])
def test_invalid_hash_name_keeps_ca_file_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trustme_ca: trustme.CA,
    httpserver: HTTPServer,
    suffix: str,
) -> None:
    _ca_paths(tmp_path, monkeypatch, trustme_ca, suffix, trustme_ca)
    _request(httpserver)


def test_valid_hash_directory_keeps_its_ca_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trustme_ca: trustme.CA,
    httpserver: HTTPServer,
) -> None:
    _ca_paths(tmp_path, monkeypatch, trustme_ca, "0", trustme.CA())
    _request(httpserver)


def test_existing_ca_file_works_with_newline_hash_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trustme_ca: trustme.CA,
    httpserver: HTTPServer,
) -> None:
    ca_file = _ca_paths(tmp_path, monkeypatch, trustme_ca, "0\n", trustme_ca)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    _request(httpserver)
