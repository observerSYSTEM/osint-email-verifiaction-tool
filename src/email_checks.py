import re
import socket
from dataclasses import asdict, dataclass
from typing import Dict, Optional, Tuple


EMAIL_REGEX = re.compile(
    r"^(?P<local>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@(?P<domain>[A-Za-z0-9.-]{1,255})$"
)


@dataclass
class EmailAnalysis:
    input_email: str
    is_syntax_valid: bool
    local_part: Optional[str]
    domain: Optional[str]
    domain_has_dot: Optional[bool]
    domain_resolves_dns: Optional[bool]
    notes: str


def _split_email(email: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Return (is_valid, local, domain) using a safe, practical regex."""
    m = EMAIL_REGEX.match(email)
    if not m:
        return False, None, None

    local = m.group("local")
    domain = m.group("domain").lower()

    # Basic hardening checks
    if domain.startswith("-") or domain.endswith("-"):
        return False, None, None
    if ".." in domain or ".." in local:
        return False, None, None
    if domain.startswith(".") or domain.endswith("."):
        return False, None, None

    return True, local, domain


def _domain_resolves(domain: str) -> bool:
    """
    Non-intrusive check: does the domain resolve to any address record?
    This is NOT mailbox verification (we do not connect to mail servers).
    """
    try:
        socket.getaddrinfo(domain, 80)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def analyse_email(email: str) -> Dict[str, object]:
    """
    Ethical OSINT-style analysis:
    - Syntax validity
    - Domain sanity checks
    - Domain DNS resolution (non-intrusive)
    """
    is_valid, local, domain = _split_email(email)

    if not is_valid or not domain:
        analysis = EmailAnalysis(
            input_email=email,
            is_syntax_valid=False,
            local_part=None,
            domain=None,
            domain_has_dot=None,
            domain_resolves_dns=None,
            notes="Invalid email syntax. Check spelling and format (e.g., name@example.com).",
        )
        return asdict(analysis)

    has_dot = "." in domain
    resolves = _domain_resolves(domain)

    notes_parts = []
    if not has_dot:
        notes_parts.append("Domain does not contain a dot; may be invalid or internal.")
    if not resolves:
        notes_parts.append("Domain did not resolve via DNS (could be misspelled or inactive).")
    if not notes_parts:
        notes_parts.append("Syntax and domain checks passed (non-intrusive).")

    analysis = EmailAnalysis(
        input_email=email,
        is_syntax_valid=True,
        local_part=local,
        domain=domain,
        domain_has_dot=has_dot,
        domain_resolves_dns=resolves,
        notes=" ".join(notes_parts),
    )
    return asdict(analysis)
