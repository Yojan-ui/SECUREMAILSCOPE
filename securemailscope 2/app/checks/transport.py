"""MX discovery and SMTP transport-security probing.

What this does: resolves MX, opens an ordinary SMTP connection, reads the
server's own EHLO advertisement, and — where STARTTLS is offered — completes a
TLS handshake to observe the negotiated version, cipher and certificate.

What this does not do: it never authenticates, never issues MAIL FROM or RCPT
TO, never sends a message, and never probes anything but the public MX hosts
the domain itself advertises. Every connection is closed with QUIT. This is the
same traffic any legitimate sending server generates, minus the mail.
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any

from ..models import Category, CheckResult, Finding, Severity, Status
from ..resolver import BaseResolver, DNSError

CHECK_ID = "transport"
CATEGORY = Category.TRANSPORT

SMTP_PORT = 25
CONNECT_TIMEOUT = 8.0
READ_TIMEOUT = 8.0
MAX_HOSTS = 3          # probe at most three MX hosts, highest priority first

# Cipher suites that should no longer appear on a mail server.
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon")


def run(domain: str, resolver: BaseResolver, probe_tls: bool = True,
        enumerate_versions: bool = True) -> CheckResult:
    started = time.monotonic()
    result = CheckResult(check_id=CHECK_ID, name="Mail Transport (MX / STARTTLS / TLS)",
                         category=CATEGORY)

    try:
        mx_records = resolver.query_optional(domain, "MX", domain)
    except DNSError as exc:
        result.error = str(exc)
        result.findings.append(
            Finding(
                id="transport.mx_lookup_failed",
                title="MX records could not be retrieved",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"The MX lookup for {domain} failed: {exc}. Transport security could "
                       "not be assessed.",
                evidence={"error": str(exc)},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    hosts = _parse_mx(mx_records)
    result.raw["mx"] = hosts

    if not hosts:
        result.findings.append(
            Finding(
                id="transport.no_mx",
                title="No MX records published",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{domain} publishes no MX records, so it does not receive mail. "
                       "Transport-security checks do not apply. Note that a domain which "
                       "sends but does not receive mail still needs SPF, DKIM and DMARC.",
                evidence={"mx_records": 0},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if not probe_tls:
        result.findings.append(
            Finding(
                id="transport.probe_skipped",
                title="TLS probing was disabled for this scan",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{len(hosts)} MX host(s) were discovered but not contacted.",
                evidence={"hosts": [h["host"] for h in hosts]},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    probes: list[dict[str, Any]] = []
    for entry in hosts[:MAX_HOSTS]:
        probes.append(_probe_host(entry["host"], enumerate_versions))
    result.raw["probes"] = probes

    reachable = [p for p in probes if p["connected"]]
    if not reachable:
        result.findings.append(
            Finding(
                id="transport.unreachable",
                title="No MX host could be contacted on port 25",
                status=Status.ERROR,
                severity=Severity.INFO,
                category=CATEGORY,
                detail="None of the MX hosts accepted a connection on port 25 within the "
                       "timeout. This commonly means the scanner's own network blocks "
                       "outbound port 25 (most cloud providers do) rather than a problem "
                       "with the domain. Transport results are therefore inconclusive.",
                evidence={"hosts": [p["host"] for p in probes],
                          "errors": [p.get("error") for p in probes]},
            )
        )
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    _evaluate_starttls(reachable, result)
    _evaluate_tls_versions(reachable, result)
    _evaluate_ciphers(reachable, result)
    _evaluate_certificates(reachable, result)

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _parse_mx(records: list[str]) -> list[dict[str, Any]]:
    hosts = []
    for record in records:
        parts = record.split()
        if len(parts) != 2:
            continue
        try:
            pref = int(parts[0])
        except ValueError:
            continue
        host = parts[1].rstrip(".").lower()
        if host in ("", "."):
            continue  # RFC 7505 null MX — the domain declares it accepts no mail
        hosts.append({"preference": pref, "host": host})
    return sorted(hosts, key=lambda h: h["preference"])


# --------------------------------------------------------------------------- probing

def _probe_host(host: str, enumerate_versions: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "host": host,
        "connected": False,
        "banner": None,
        "starttls": False,
        "ehlo_extensions": [],
        "tls": None,
        "certificate": None,
        "cert_verified": None,
        "cert_error": None,
        "versions": {},
        "error": None,
    }

    try:
        sock = socket.create_connection((host, SMTP_PORT), timeout=CONNECT_TIMEOUT)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    try:
        sock.settimeout(READ_TIMEOUT)
        out["connected"] = True
        out["banner"] = _read_response(sock)[:200]

        sock.sendall(b"EHLO securemailscope.probe\r\n")
        ehlo = _read_response(sock)
        out["ehlo_extensions"] = [
            line[4:].strip().upper() for line in ehlo.splitlines() if len(line) > 4
        ]
        out["starttls"] = any(e.startswith("STARTTLS") for e in out["ehlo_extensions"])

        if out["starttls"]:
            sock.sendall(b"STARTTLS\r\n")
            resp = _read_response(sock)
            if resp.startswith("220"):
                _negotiate(sock, host, out)
            else:
                out["error"] = f"STARTTLS refused: {resp[:100]}"
                _quit(sock)
        else:
            _quit(sock)
    except Exception as exc:
        out["error"] = out["error"] or f"{type(exc).__name__}: {exc}"
        try:
            sock.close()
        except Exception:
            pass

    if enumerate_versions and out["starttls"]:
        out["versions"] = _enumerate_versions(host)

    return out


def _negotiate(sock: socket.socket, host: str, out: dict[str, Any]) -> None:
    """Complete the handshake permissively to observe what is offered, then
    re-verify strictly to judge the certificate chain."""
    permissive = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    permissive.check_hostname = False
    permissive.verify_mode = ssl.CERT_NONE
    try:
        tls_sock = permissive.wrap_socket(sock, server_hostname=host)
    except Exception as exc:
        out["error"] = f"TLS handshake failed: {type(exc).__name__}: {exc}"
        try:
            sock.close()
        except Exception:
            pass
        return

    cipher = tls_sock.cipher()
    out["tls"] = {
        "version": tls_sock.version(),
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
    }
    der = tls_sock.getpeercert(binary_form=True)
    if der:
        out["certificate"] = _parse_certificate(der)
    _quit(tls_sock)

    verified = _verify_chain(host)
    out["cert_verified"] = verified["ok"]
    out["cert_error"] = verified.get("error")


def _verify_chain(host: str) -> dict[str, Any]:
    """Second connection using the system trust store and hostname checking."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, SMTP_PORT), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            _read_response(sock)
            sock.sendall(b"EHLO securemailscope.probe\r\n")
            _read_response(sock)
            sock.sendall(b"STARTTLS\r\n")
            if not _read_response(sock).startswith("220"):
                return {"ok": None, "error": "STARTTLS refused on verification pass"}
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                _quit(tls_sock)
            return {"ok": True}
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "error": exc.verify_message or str(exc)}
    except Exception as exc:
        return {"ok": None, "error": f"{type(exc).__name__}: {exc}"}


def _enumerate_versions(host: str) -> dict[str, Any]:
    """Determine which TLS versions the server will accept, one per connection."""
    results: dict[str, Any] = {}
    candidates = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for label, version in candidates:
        if version is None:
            results[label] = {"supported": None, "reason": "not available in this OpenSSL build"}
            continue
        results[label] = _try_version(host, version)
    return results


def _try_version(host: str, version: Any) -> dict[str, Any]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        # Legacy versions are disabled by OpenSSL's default security level;
        # lowering it lets us *observe* whether the server would accept them.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, OSError) as exc:
        return {"supported": None, "reason": f"client cannot offer this version: {exc}"}

    try:
        with socket.create_connection((host, SMTP_PORT), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            _read_response(sock)
            sock.sendall(b"EHLO securemailscope.probe\r\n")
            _read_response(sock)
            sock.sendall(b"STARTTLS\r\n")
            if not _read_response(sock).startswith("220"):
                return {"supported": None, "reason": "STARTTLS refused"}
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher()
                out = {
                    "supported": True,
                    "negotiated": tls_sock.version(),
                    "cipher": cipher[0] if cipher else None,
                }
                _quit(tls_sock)
                return out
    except ssl.SSLError:
        return {"supported": False}
    except Exception as exc:
        return {"supported": None, "reason": f"{type(exc).__name__}: {exc}"}


def _parse_certificate(der: bytes) -> dict[str, Any]:
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return {"error": f"could not parse certificate: {exc}"}

    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_desc, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC ({pub.curve.name})", pub.curve.key_size
    else:
        key_desc, key_bits = type(pub).__name__, None

    now = datetime.now(timezone.utc)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - now).days,
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "san": san,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "key_type": key_desc,
        "key_bits": key_bits,
        "self_signed": cert.issuer == cert.subject,
    }


def _read_response(sock: socket.socket) -> str:
    """Read one complete SMTP reply (handles multi-line 250- continuations)."""
    buf = b""
    while b"\r\n" not in buf or _incomplete(buf):
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf.decode("utf-8", errors="replace")


def _incomplete(buf: bytes) -> bool:
    lines = buf.split(b"\r\n")
    for line in reversed(lines):
        if line:
            return len(line) >= 4 and line[3:4] == b"-"
    return True


def _quit(sock: Any) -> None:
    try:
        sock.sendall(b"QUIT\r\n")
        sock.recv(512)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


# --------------------------------------------------------------------------- findings

def _evaluate_starttls(probes: list[dict[str, Any]], result: CheckResult) -> None:
    without = [p["host"] for p in probes if not p["starttls"]]
    if without:
        result.findings.append(
            Finding(
                id="transport.no_starttls",
                title=f"{len(without)} MX host(s) do not offer STARTTLS",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                category=CATEGORY,
                detail=f"{', '.join(without)} accepted a connection but did not advertise "
                       "STARTTLS. Mail delivered to these hosts crosses the internet in "
                       "cleartext, readable and modifiable by anyone on the path — including "
                       "message bodies, attachments and any credentials or reset links they "
                       "contain.",
                evidence={"hosts_without_starttls": without},
                remediation="Enable STARTTLS with a valid certificate on every MX host.",
                reference="RFC 3207",
            )
        )
    else:
        result.findings.append(
            Finding(
                id="transport.starttls_ok",
                title="All probed MX hosts offer STARTTLS",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"{len(probes)} host(s) advertise STARTTLS and completed a TLS "
                       "handshake.",
                evidence={"hosts": [p["host"] for p in probes]},
            )
        )


def _evaluate_tls_versions(probes: list[dict[str, Any]], result: CheckResult) -> None:
    legacy: dict[str, list[str]] = {"TLSv1": [], "TLSv1.1": []}
    no_modern: list[str] = []

    for probe in probes:
        versions = probe.get("versions") or {}
        for label in ("TLSv1", "TLSv1.1"):
            if versions.get(label, {}).get("supported"):
                legacy[label].append(probe["host"])
        if versions:
            modern = any(versions.get(v, {}).get("supported") for v in ("TLSv1.2", "TLSv1.3"))
            if not modern:
                no_modern.append(probe["host"])

    enabled = {k: v for k, v in legacy.items() if v}
    if enabled:
        listed = "; ".join(f"{k} on {', '.join(v)}" for k, v in enabled.items())
        result.findings.append(
            Finding(
                id="transport.legacy_tls",
                title="Deprecated TLS versions are accepted",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail=f"{listed}. TLS 1.0 and 1.1 were deprecated by RFC 8996 and are "
                       "vulnerable to downgrade and cipher attacks. An attacker who can "
                       "influence the handshake can force the connection onto the weaker "
                       "version and attack it there.",
                evidence={"legacy_versions": enabled},
                remediation="Set the minimum TLS version to 1.2 on all MX hosts.",
                reference="RFC 8996",
            )
        )

    if no_modern:
        result.findings.append(
            Finding(
                id="transport.no_modern_tls",
                title="MX host(s) do not support TLS 1.2 or 1.3",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                category=CATEGORY,
                detail=f"{', '.join(no_modern)} accepted neither TLS 1.2 nor TLS 1.3. Senders "
                       "with modern-only configurations cannot establish an encrypted "
                       "connection at all, forcing either cleartext delivery or bounce.",
                evidence={"hosts": no_modern},
                remediation="Enable TLS 1.2 and TLS 1.3.",
                reference="RFC 8996",
            )
        )

    if not enabled and not no_modern and any(p.get("versions") for p in probes):
        supported = sorted({
            label for p in probes for label, v in (p.get("versions") or {}).items()
            if v.get("supported")
        })
        result.findings.append(
            Finding(
                id="transport.tls_versions_ok",
                title="Only modern TLS versions are accepted",
                status=Status.PASS,
                severity=Severity.INFO,
                category=CATEGORY,
                detail=f"Supported versions: {', '.join(supported) or 'TLS 1.2+'}. "
                       "TLS 1.0 and 1.1 are refused.",
                evidence={"supported": supported},
            )
        )


def _evaluate_ciphers(probes: list[dict[str, Any]], result: CheckResult) -> None:
    weak: list[dict[str, Any]] = []
    for probe in probes:
        observed = []
        if probe.get("tls", {}) and probe["tls"].get("cipher"):
            observed.append(probe["tls"]["cipher"])
        for v in (probe.get("versions") or {}).values():
            if v.get("cipher"):
                observed.append(v["cipher"])
        for cipher in set(observed):
            if any(marker in cipher.upper() for marker in _WEAK_CIPHER_MARKERS):
                weak.append({"host": probe["host"], "cipher": cipher})

    if weak:
        result.findings.append(
            Finding(
                id="transport.weak_cipher",
                title="Weak cipher suites negotiated",
                status=Status.FAIL,
                severity=Severity.HIGH,
                category=CATEGORY,
                detail="These suites are considered broken or badly weakened: "
                       + "; ".join(f"{w['cipher']} on {w['host']}" for w in weak)
                       + ". A negotiated connection using them does not provide meaningful "
                         "confidentiality against a capable attacker.",
                evidence={"weak_ciphers": weak},
                remediation="Restrict the cipher list to AEAD suites (AES-GCM, ChaCha20-"
                            "Poly1305) with forward secrecy.",
                reference="RFC 7525",
            )
        )


def _evaluate_certificates(probes: list[dict[str, Any]], result: CheckResult) -> None:
    for probe in probes:
        cert = probe.get("certificate")
        host = probe["host"]
        if not cert or cert.get("error"):
            continue

        if cert.get("expired"):
            result.findings.append(
                Finding(
                    id=f"transport.cert_expired.{host}",
                    title=f"Certificate on {host} has expired",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    detail=f"The certificate expired on {cert['not_after']}. Senders that "
                           "validate certificates — which MTA-STS in enforce mode requires — "
                           "will refuse to deliver, while senders using opportunistic TLS "
                           "silently accept it, so the failure mode is inconsistent and "
                           "hard to notice.",
                    evidence={"host": host, "not_after": cert["not_after"],
                              "subject": cert["subject"]},
                    remediation="Renew the certificate and automate renewal.",
                )
            )
        elif cert.get("days_until_expiry", 999) < 30:
            result.findings.append(
                Finding(
                    id=f"transport.cert_expiring.{host}",
                    title=f"Certificate on {host} expires in "
                          f"{cert['days_until_expiry']} days",
                    status=Status.WARN,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail=f"Expiry is {cert['not_after']}. If MTA-STS is enforced, expiry "
                           "causes inbound mail to be rejected outright.",
                    evidence={"host": host, "days_until_expiry": cert["days_until_expiry"]},
                    remediation="Renew now and put automated renewal in place.",
                )
            )

        if cert.get("self_signed"):
            result.findings.append(
                Finding(
                    id=f"transport.cert_self_signed.{host}",
                    title=f"Certificate on {host} is self-signed",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail="A self-signed certificate cannot be validated against any trust "
                           "store, so it provides encryption but no assurance the server is "
                           "the right one — an on-path attacker can substitute their own.",
                    evidence={"host": host, "subject": cert["subject"]},
                    remediation="Install a certificate from a publicly trusted CA.",
                )
            )
        elif probe.get("cert_verified") is False:
            result.findings.append(
                Finding(
                    id=f"transport.cert_invalid.{host}",
                    title=f"Certificate chain on {host} failed validation",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    detail=f"Validation against the system trust store failed: "
                           f"{probe.get('cert_error')}. MTA-STS in enforce mode requires a "
                           "valid, hostname-matching chain, so this configuration would "
                           "break enforced delivery.",
                    evidence={"host": host, "error": probe.get("cert_error"),
                              "subject": cert.get("subject"), "san": cert.get("san")},
                    remediation="Serve the full chain and ensure the MX hostname appears in "
                                "the certificate's subject alternative names.",
                )
            )

        if cert.get("key_type") == "RSA" and (cert.get("key_bits") or 0) < 2048:
            result.findings.append(
                Finding(
                    id=f"transport.cert_weak_key.{host}",
                    title=f"Certificate on {host} uses a {cert['key_bits']}-bit RSA key",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    detail="RSA keys below 2048 bits are below every current baseline "
                           "requirement and are not considered to provide adequate strength.",
                    evidence={"host": host, "key_bits": cert["key_bits"]},
                    remediation="Reissue the certificate with a 2048-bit RSA or P-256 EC key.",
                )
            )

        if "sha1" in (cert.get("signature_algorithm") or "").lower():
            result.findings.append(
                Finding(
                    id=f"transport.cert_sha1.{host}",
                    title=f"Certificate on {host} is signed with SHA-1",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    detail="SHA-1 has practical collision attacks and is rejected by modern "
                           "trust stores; the certificate provides no reliable authentication.",
                    evidence={"host": host,
                              "signature_algorithm": cert["signature_algorithm"]},
                    remediation="Reissue with a SHA-256 signature.",
                )
            )
