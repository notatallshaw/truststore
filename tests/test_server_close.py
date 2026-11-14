import asyncio
import ssl

import pytest
import urllib3
from aiohttp import web

import truststore
from tests.conftest import Server


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_server_close_releases_tls_socket(
    server: Server, monkeypatch: pytest.MonkeyPatch, cleanup_fails: bool
) -> None:
    """Teardown closes physical sockets while the client keeps its pool alive."""
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with (
        urllib3.PoolManager(ssl_context=context) as manager,
        manager.connection_from_url(server.base_url) as pool,
    ):
        response = await asyncio.to_thread(pool.request, "GET", "/")
        assert response.status == 200
        transports = tuple(server._transports)
        assert transports
        sockets = [transport.get_extra_info("socket") for transport in transports]
        assert all(sock is not None and sock.fileno() >= 0 for sock in sockets)

        if cleanup_fails:
            original_cleanup = web.AppRunner.cleanup
            failure = RuntimeError("cleanup failed")

            async def fail_after_cleanup(runner: web.AppRunner) -> None:
                await original_cleanup(runner)
                raise failure

            with monkeypatch.context() as patch:
                patch.setattr(web.AppRunner, "cleanup", fail_after_cleanup)
                with pytest.raises(RuntimeError) as raised:
                    await server.close()
            assert raised.value is failure
            assert not server._closed
        else:
            await server.close()

        assert all(sock.fileno() == -1 for sock in sockets)
        assert not server._transports
        await server.close()
        await server.close()
