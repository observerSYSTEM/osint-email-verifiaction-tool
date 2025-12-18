import re
import socket
from dataclasses import asdict, dataclass
from typing import Dict, Optional, Tuple, List


EMAIL_REGEX = re.compile(
    r"^(?P<local>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@(?P<domain>[A-Za-z0-9.-]{1,255})$"
)

# Common scam/social-engineering keywords (expand over time)
SUSPICIOUS_KEYWORDS = {
    "billing", "invoice", "refund", "payment", "charged", "subscription", "renewal",
    "security", "verify", "verification", "urgent", "immediately", "action required",
    "support", "account", "password", "suspended", "limited", "confirm"
}

# Brand → official domains (small starter set; you can expand)
BRAND_OFFICIAL_DOMAINS = {
    "norton": {"norton.com", "symantec.com"},
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com"},
}

# Not always malicious, but often used in scams; treated as a weak signal
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me", "protonmail.com"
}


@dataclass
class EmailAnalysis:
    input_email: str
    is_syntax_valid: bool
    local_part: Optional[str]
    domain: Optional[str]
    domain_has_dot: Optional[bool]
    domain_resolves_dns: Optional[bool]
    risk_score: Optional[int]
    risk_level: Optional[str]
    risk_reasons: List[str]
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


def _risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _score_risk(local: str, domain: str, resolves: bool, has_dot: bool) -> Tuple[int, List[str]]:
    """
    Heuristic risk scoring (OSINT-style):
    - Brand impersonation signals
    - Suspicious keyword signals
    - Weak technical signals (DNS / formatting)
    """
    score = 0
    reasons: List[str] = []

    local_l = local.lower()
    domain_l = domain.lower()

    # Technical signals
    if not has_dot:
        score += 15
        reasons.append("Domain does not contain a dot (may be invalid or internal).")

    if not resolves:
        score += 30
        reasons.append("Domain did not resolve via DNS (could be inactive or misspelled).")

    # Suspicious keyword signals
    hits = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in local_l:
            hits.append(kw)

    # Add up to 3 keyword hits to avoid inflating score
    for kw in sorted(hits)[:3]:
        score += 10
        reasons.append(f"Suspicious keyword detected: {kw}")

    # Brand impersonation signals
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        brand_in_local = brand in local_l
        brand_in_domain = brand in domain_l

        if brand_in_local and domain_l not in official_domains:
            score += 60
            reasons.append(f"Brand impersonation keyword detected: {brand}")
            reasons.append("Domain does not match official brand domain.")

        # If domain contains brand string but isn't official, possible typosquatting / lookalike
        if brand_in_domain and domain_l not in official_domains:
            score += 35
            reasons.append(f"Possible lookalike/typosquat domain contains brand: {brand}")

    # Weak signal: free provider + finance/security keywords in local part
    if domain_l in FREE_EMAIL_PROVIDERS and any(k in local_l for k in ("billing", "invoice", "refund", "support", "verify", "security")):
        score += 20
        reasons.append("Free email provider used with billing/security wording (common in scams).")

    # Cap score to 100
    score = min(score, 100)

    # If nothing suspicious found, add an explicit reason
    if score == 0:
        reasons.append("No common scam indicators detected (heuristics only).")

    return score, reasons


def analyse_email(email: str) -> Dict[str, object]:
    """
    Ethical OSINT-style analysis:
    - Syntax validity
    - Domain sanity checks
    - Domain DNS resolution (non-intrusive)
    - Risk scoring (heuristics)
    """
    is_valid, local, domain = _split_email(email)

    if not is_valid or not domain or not local:
        analysis = EmailAnalysis(
            input_email=email,
            is_syntax_valid=False,
            local_part=None,
            domain=None,
            domain_has_dot=None,
            domain_resolves_dns=None,
            risk_score=None,
            risk_level=None,
            risk_reasons=[],
            notes="Invalid email syntax. Check spelling and format (e.g., name@example.com).",
        )
        return asdict(analysis)

    has_dot = "." in domain
    resolves = _domain_resolves(domain)

    score, reasons = _score_risk(local, domain, resolves, has_dot)
    level = _risk_level(score)

    notes = "Heuristic assessment only. Use alongside message/header analysis and context."

    analysis = EmailAnalysis(
        input_email=email,
        is_syntax_valid=True,
        local_part=local,
        domain=domain,
        domain_has_dot=has_dot,
        domain_resolves_dns=resolves,
        risk_score=score,
        risk_level=level,
        risk_reasons=reasons,
        notes=notes,
    )
    return asdict(analysis)
