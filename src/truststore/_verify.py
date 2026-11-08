import ssl
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PeerVerificationState:
    """Verification settings captured before temporary context changes."""

    # Keep the context because capath certificates can resolve during handshake.
    context: ssl.SSLContext = field(repr=False, compare=False)
    check_hostname: bool
    verify_flags: ssl.VerifyFlags
    verify_mode: ssl.VerifyMode

    @classmethod
    def capture(cls, context: ssl.SSLContext) -> "PeerVerificationState":
        """Capture settings used by the platform verifier."""
        return cls(
            context=context,
            check_hostname=context.check_hostname,
            verify_flags=context.verify_flags,
            verify_mode=context.verify_mode,
        )

    def custom_ca_certs(self) -> tuple[bytes, ...]:
        """Return CA certificates after OpenSSL has resolved lazy capath entries."""
        return tuple(self.context.get_ca_certs(binary_form=True))
