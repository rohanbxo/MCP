"""Deterministic rule engine (build spec Section 7).

Each text rule is a function ``(text, channel, source) -> list[Finding]``.
Regexes are compiled once at module load, case-insensitive. Rules emit a
``Finding`` with ``score == 1.0`` and ``detector == "rule:<id>"``.

R5 (schema drift) is not a text regex; it is computed by the firewall against a
stored manifest hash. The helpers for it live here so all rule logic is in one
place.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Callable, Iterable

from .models import Channel, Finding, Severity

# Cap matched spans so a finding never carries a huge blob of text.
_MAX_MATCH = 200

STATE_FILE = ".mcp_firewall_state.json"


def _clip(s: str) -> str:
    s = s.strip()
    return s if len(s) <= _MAX_MATCH else s[: _MAX_MATCH - 3] + "..."


def _finding(
    *,
    rule_id: str,
    channel: Channel,
    source: str,
    severity: Severity,
    matched: str,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(
        channel=channel,
        source=source,
        detector=f"rule:{rule_id}",
        severity=severity,
        score=1.0,
        matched_text=_clip(matched),
        message=message,
        remediation=remediation,
    )


# --------------------------------------------------------------------------- #
# R1 — shell / code-execution sinks
# --------------------------------------------------------------------------- #
_R1_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bsubprocess\b[^\n]*\bshell\s*=\s*True\b",
        r"\bchild_process\b\s*\.\s*exec\b",
        r"(?<![\w.])eval\s*\(",
        r"(?<![\w.])exec\s*\(",
    )
]


def r1_shell_sink(text: str, channel: Channel, source: str) -> list[Finding]:
    for pat in _R1_PATTERNS:
        m = pat.search(text)
        if m:
            return [
                _finding(
                    rule_id="R1_shell_sink",
                    channel=channel,
                    source=source,
                    severity="high",
                    matched=m.group(0),
                    message=(
                        "Reference to a command/code-execution sink "
                        f"({m.group(0).strip()!r}). Such sinks enable command "
                        "injection if reachable from tool input."
                    ),
                    remediation=(
                        "Avoid shelling out to the OS or evaluating dynamic code. "
                        "Use a fixed, parameterized API and never pass model- or "
                        "user-controlled text to shell/eval/exec."
                    ),
                )
            ]
    return []


# --------------------------------------------------------------------------- #
# R2 — secret / sensitive-path access
# --------------------------------------------------------------------------- #
_R2_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"~/\.ssh\b",
        r"\bid_rsa\b",
        r"(?<![\w.])\.env\b",
        r"\bAWS_SECRET\w*\b",
        r"\bprivate key\b",
        r"\bapi[_ ]?key\b",
        r"\bpassword\s*=",
    )
]


def r2_secret_path(text: str, channel: Channel, source: str) -> list[Finding]:
    for pat in _R2_PATTERNS:
        m = pat.search(text)
        if m:
            return [
                _finding(
                    rule_id="R2_secret_path",
                    channel=channel,
                    source=source,
                    severity="high",
                    matched=m.group(0),
                    message=(
                        "Reference to sensitive data or a secret location "
                        f"({m.group(0).strip()!r}). Tools should not read or expose "
                        "credentials, private keys, or environment secrets."
                    ),
                    remediation=(
                        "Do not access SSH keys, .env files, or credential material "
                        "from tool logic or descriptions. Scope tools to their "
                        "declared purpose only."
                    ),
                )
            ]
    return []


# --------------------------------------------------------------------------- #
# R3 — instruction-override / hidden-command phrases
# --------------------------------------------------------------------------- #
_R3_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bignore\s+(?:all\s+)?previous\s+instructions\b",
        r"\bdo\s+not\s+(?:tell|mention|inform)\s+the\s+user\b",
        r"<important>",
        r"\byou\s+must\s+(?:now|instead)\b",
        r"\bdisregard\b",
    )
]


def r3_override_phrase(text: str, channel: Channel, source: str) -> list[Finding]:
    for pat in _R3_PATTERNS:
        m = pat.search(text)
        if m:
            extra = ""
            if channel == "description":
                extra = (
                    " This appears in a tool *description*, which is injected into "
                    "model context as trusted text - descriptions should describe, "
                    "not command."
                )
            return [
                _finding(
                    rule_id="R3_override_phrase",
                    channel=channel,
                    source=source,
                    severity="critical",
                    matched=m.group(0),
                    message=(
                        "Instruction-override / hidden-directive phrase "
                        f"({m.group(0).strip()!r}). Classic prompt-injection / "
                        "tool-poisoning signature." + extra
                    ),
                    remediation=(
                        "Remove imperative instructions from the tool description; "
                        "descriptions are injected into model context as trusted "
                        "text. Treat tool output as untrusted data, not commands."
                    ),
                )
            ]
    return []


# --------------------------------------------------------------------------- #
# R4 — exfiltration: external URL + an exfil verb in the same text
# --------------------------------------------------------------------------- #
_R4_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_R4_VERB = re.compile(
    r"\b(?:send|post|upload|exfiltrate|forward)\b", re.IGNORECASE
)


def r4_exfil(text: str, channel: Channel, source: str) -> list[Finding]:
    url = _R4_URL.search(text)
    verb = _R4_VERB.search(text)
    if url and verb:
        return [
            _finding(
                rule_id="R4_exfil",
                channel=channel,
                source=source,
                severity="high",
                matched=f"{verb.group(0)} ... {url.group(0)}",
                message=(
                    "Possible data-exfiltration instruction: an external URL "
                    f"({url.group(0)}) combined with an exfil verb "
                    f"({verb.group(0)!r}) in the same text."
                ),
                remediation=(
                    "Tools must not be directed to send/post/upload data to "
                    "external endpoints. Remove outbound-transfer instructions and "
                    "review where tool output is allowed to flow."
                ),
            )
        ]
    return []


# Ordered list of all text rules.
TEXT_RULES: list[Callable[[str, Channel, str], list[Finding]]] = [
    r1_shell_sink,
    r2_secret_path,
    r3_override_phrase,
    r4_exfil,
]


def run_rules(text: str | None, channel: Channel, source: str) -> list[Finding]:
    """Run every text rule over ``text`` and aggregate the findings."""
    if not text:
        return []
    findings: list[Finding] = []
    for rule in TEXT_RULES:
        findings.extend(rule(text, channel, source))
    return findings


# --------------------------------------------------------------------------- #
# R5 — schema / manifest drift (severity medium)
# --------------------------------------------------------------------------- #
def manifest_hash(tools: Iterable[tuple[str, str | None, dict]]) -> str:
    """Stable hash of the tool manifest (sorted name + description + schema)."""
    items = sorted(
        (
            name,
            description or "",
            json.dumps(schema or {}, sort_keys=True, default=str),
        )
        for name, description, schema in tools
    )
    blob = json.dumps(items, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_state(state_path: str) -> dict:
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(state_path: str, state: dict) -> None:
    try:
        with open(state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
    except OSError:
        # State persistence is best-effort; never fatal to a scan.
        pass


def check_schema_drift(
    server_key: str,
    current_hash: str,
    state_path: str = STATE_FILE,
) -> list[Finding]:
    """Compare ``current_hash`` to the stored hash for ``server_key``.

    First run records the hash and emits no finding. A later change emits one
    R5 finding on the ``schema`` channel and updates the stored hash.
    """
    state = _load_state(state_path)
    manifests: dict = state.setdefault("manifests", {})
    previous = manifests.get(server_key)

    findings: list[Finding] = []
    if previous is not None and previous != current_hash:
        findings.append(
            _finding(
                rule_id="R5_schema_drift",
                channel="schema",
                source=server_key,
                severity="medium",
                matched=f"{previous[:12]}... -> {current_hash[:12]}...",
                message=(
                    "Tool manifest changed since last scan (name/description/"
                    "schema differ). Silent drift can mean a rug-pull: a tool that "
                    "passed review is later swapped for a poisoned variant."
                ),
                remediation=(
                    "Re-review the changed tool definitions and confirm the change "
                    "is expected. Pin or sign trusted MCP server versions."
                ),
            )
        )

    manifests[server_key] = current_hash
    _save_state(state_path, state)
    return findings


def reset_state(state_path: str = STATE_FILE) -> None:
    """Remove the persisted drift state (useful for tests / fresh baselines)."""
    try:
        os.remove(state_path)
    except OSError:
        pass
