import subprocess
import sys
import textwrap


def test_reload_preserves_public_api():
    """Reload the package without replacing its public implementation objects."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent("""
                import importlib
                import truststore

                exports = {name: getattr(truststore, name) for name in truststore.__all__}
                importlib.reload(truststore)

                for name, value in exports.items():
                    assert getattr(truststore, name) is value
                """),
        ],
        check=True,
    )
