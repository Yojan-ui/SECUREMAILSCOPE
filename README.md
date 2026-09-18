# SECUREMAILSCOPE
# SecureMailScope — architecture and decisions

Status as of 19 September 2026: working prototype complete, 59 tests passing. Delivered
as `securemailscope.zip`. Built to Yashas's brief; not an assigned SIH problem statement.

## Stack (as decided)

FastAPI backend, server-rendered with Jinja2 + HTMX for live scan progress — a single
deployable, no separate frontend build. dnspython for DNS, raw `ssl`/`socket` for SMTP
transport probing, ReportLab for the PDF, SQLite for scan history and result caching.

LLM narrative layer is provider-agnostic (Anthropic default, OpenAI-compatible adapter
for Groq/Together/OpenRouter if credits are a constraint) with a full deterministic
rule-based fallback, so the tool never depends on a live API call.

## Decisions worth remembering

**DMARC carries 30 of the 100 points**, more than any other check. Rationale: it is the
only control that tells a receiver to *reject*. SPF and DKIM produce a verdict; DMARC
turns that verdict into action. A domain with flawless SPF and DKIM and no DMARC is still
freely spoofable. Remaining weights: transport 25, SPF 20, DKIM 15, MTA-STS 7, TLS-RPT 3,
BIMI 0 (brand presentation, not a security control).

**Inconclusive checks are excluded from the denominator, never scored as failures.** This
is the property that decides whether the tool is trustworthy. If the host blocks outbound
port 25 — most cloud providers do — the report says transport was not assessed. A network
restriction on the scanner must never be reported as a weakness in the assessed domain.
Same rule applies to filtered resolvers, proxy failures reaching an MTA-STS policy host,
and any check that raises. Covered by `tests/test_network_honesty.py`.

**A clean domain scores 100.** No curve, no floor of manufactured deductions. This is the
answer to the judge's question "what happens with a perfectly configured domain?" — and
it is enforced by test, not by hope.

**The AI layer is a wrapper, never a source.** The model receives only the engine's
serialized findings and is validated before display (`app/ai/validation.py`): rejected if
it states a score or grade other than the computed one, cites a nonexistent finding id, or
proposes remediation / describes attack scenarios when the engine found nothing wrong. On
rejection it silently falls back to the rule-based writer rather than showing caveated
output.

**Relaxed DMARC alignment is reported but not scored.** It is the RFC default and correct
for most organisations; treating it as a weakness would penalise nearly every
well-configured domain and devalue the score.

**MTA-STS, TLS-RPT and DKIM are marked not-applicable rather than failing** when the
domain publishes no MX (inbound controls with nothing to protect) or an SPF record
authorising no senders (the documented "this domain sends no mail" declaration).

**MTA-STS fetch errors are classified by fault.** An HTTP status or a TLS error from the
policy host is the domain's misconfiguration and scores. A connection that never completed
is inconclusive, because it may be the scanner's own egress.

**DKIM absence is reported as "not discovered", never "absent".** Selectors cannot be
enumerated from DNS, so the tool probes ~40 common ones and states plainly that a negative
result does not prove DKIM is unconfigured.

## Known constraints

- Needs outbound UDP/TCP 53 and TCP 25. Cloud hosts usually block 25 — set
  `SMS_DISABLE_TLS_PROBE=1` there, or run the engine on a VM where it is open.
- `--resolver doh` switches to DNS-over-HTTPS where UDP/53 is filtered.
- Tests run entirely offline against recorded DNS fixtures, so CI needs no network.

## Open items

- Stretch goal from the original brief not yet built: a classifier flagging configuration
  patterns statistically correlated with known BEC/phishing incidents. Would need a
  labelled dataset; the deterministic ruleset covers the demo without it.
- Deployment not yet done (Render/Vercel + VM for the DNS engine was the suggestion).
- No live scan has been run yet — the build sandbox blocked DNS and port 25. First real
  validation should be scanning 2-3 known domains locally.
