# SecureMailScope

Passive cryptographic and email-authentication posture assessment. Give it a domain; it
reads what that domain publishes about how its mail is authenticated and encrypted,
scores it, and explains in plain English what an attacker could do with each gap.

Everything it reports comes from a real lookup. There is no mocked data anywhere in the
scanning path.

## What it checks

**Authentication** — SPF record validity and terminal `all` qualifier, the RFC 7208
10-lookup limit counted by actually walking `include:` chains rather than counting terms,
overly broad ranges and the deprecated `ptr` mechanism. DKIM selector discovery across the
selectors used by the major mail platforms, with each public key decoded and its true
modulus size measured. DMARC policy strictness, subdomain policy, partial enforcement via
`pct`, alignment mode and whether anyone actually receives the reports.

**Transport** — MX discovery, STARTTLS advertisement, which TLS versions each host will
actually accept (probed one version per connection), negotiated cipher suites, and
certificate chain validation, expiry, key size and signature algorithm.

**Policy** — MTA-STS: both the DNS record *and* the HTTPS-hosted policy file, with its
mode parsed, because a record without a reachable policy provides no protection. TLS-RPT
reporting. BIMI where present, reported but not scored.

## Scoring

Each check owns a share of 100 points, weighted by how much attacker leverage a failure in
that check actually grants:

| Check | Weight | Why |
|---|---|---|
| DMARC | 30 | The only control that tells a receiver to *reject*. Flawless SPF and DKIM still leave a domain spoofable without it. |
| Transport | 25 | Determines whether mail crosses the internet readable. |
| SPF | 20 | One of the two signals DMARC evaluates. |
| DKIM | 15 | The other, and the one that survives forwarding. |
| MTA-STS | 7 | Prevents STARTTLS stripping. |
| TLS-RPT | 3 | Visibility into transport failures. |
| BIMI | 0 | Brand presentation, not a security control. |

Each finding removes a fraction of its check's points by severity — critical 100%, high
60%, medium 30%, low 10% — and no single check can deduct more than its own weight.

Two properties are enforced in code and covered by tests:

- **A check that could not complete is excluded from the denominator**, not scored as a
  failure. If your host blocks outbound port 25, the report says transport was not
  assessed; it never reports a network restriction on the scanner as a weakness in the
  assessed domain.
- **A domain with nothing wrong scores 100.** There is no curve and no floor of
  manufactured deductions. "Nothing to fix" is a reachable result.

## The AI layer

The narrative is a wrapper around findings, never a source of them. The model receives
only the engine's serialized output, and every response is validated before it is shown
(`app/ai/validation.py`). A narrative is rejected and replaced by the built-in rule-based
writer if it states a score or grade other than the computed one, cites a finding id that
does not exist, or — the case that matters most on a demo stage — proposes remediation or
describes attack scenarios when the engine found nothing wrong.

The rule-based writer is not a stub. It produces a complete, specific report on its own,
so the tool works with no API key, no network access to a model provider, and no risk of a
rate limit killing a live demo.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env          # optional: add an API key for the AI narrative

# web app
uvicorn app.main:app --reload --port 8000

# command line
python cli.py example.com
python cli.py example.com --json
python cli.py example.com --pdf report.pdf
python cli.py example.com --no-tls-probe --resolver doh
```

Then open <http://localhost:8000>. The API is self-documenting at `/docs`.

### Network requirements

The scanning engine needs outbound **UDP/TCP 53** for DNS and outbound **TCP 25** for the
transport checks. Most cloud providers block port 25 by default; run the engine on a VM
where it is open, or set `SMS_DISABLE_TLS_PROBE=1` and the transport section is honestly
reported as not assessed. If UDP/53 is filtered, `--resolver doh` switches to
DNS-over-HTTPS.

## Tests

```bash
pytest -q
```

52 tests run against recorded DNS fixtures (`tests/fixtures/`), so the parsing, scoring and
grounding logic is verified deterministically and offline. The fixtures cover a
well-configured domain, a comprehensively misconfigured one, a maximally spoofable one
(`v=spf1 +all`, no DMARC), and a domain that declares it sends and receives no mail.

## Scope — what this tool deliberately does not do

This is a passive, read-only assessment. It performs public DNS lookups, an HTTPS GET of
the domain's own published MTA-STS policy, and SMTP connections to the hosts the domain
advertises in its MX records — used only to read the server's STARTTLS advertisement and
complete a TLS handshake, then closed with `QUIT`.

It does not send test phishing messages. It does not attempt authentication or
authentication bypass. It does not relay or deliver mail. It does not access mailbox
contents. It does not attempt to exploit any weakness it identifies. Lookups are cached
and rate-limited per domain, so a scan generates the same traffic as one legitimate
sending server, minus the mail.

Every check runs against information the domain owner chose to publish.

## Layout

```
app/
  models.py          Finding / CheckResult / Assessment — the data contract
  resolver.py        System, DoH and fixture resolvers; TTL cache; rate limiter
  checks/
    spf.py           RFC 7208
    dkim.py          RFC 6376 / 8301, real key-size measurement
    dmarc.py         RFC 7489
    policy.py        MTA-STS (8461), TLS-RPT (8460), BIMI
    transport.py     MX, STARTTLS, TLS versions, certificates
  engine/
    scanner.py       Orchestration, domain normalisation
    scoring.py       Weights, severity penalties, grade bands
  ai/
    __init__.py      Narrative dispatch and prompt construction
    llm.py           Anthropic + OpenAI-compatible providers
    validation.py    Grounding checks — the guarantee against invented findings
    deterministic.py Rule-based fallback writer
  report.py          PDF generation
  storage.py         SQLite scan history and result cache
  web/               Jinja templates and CSS
cli.py               Command-line entry point
tests/               Fixture-backed test suite
```
