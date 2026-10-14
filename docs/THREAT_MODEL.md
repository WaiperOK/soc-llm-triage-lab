# Threat Model

## Assets

- triage input events
- playbook corpus
- triage outputs and confidence labels
- telemetry stream
- LLM backend credentials (optional)

## Threats and controls

1. Malformed payload crash
- Threat: invalid JSON, missing fields
- Control: strict decode + validation with 400 response

2. Prompt injection in incident text
- Threat: attacker-controlled log fields (User-Agent, URLs, usernames) steer the LLM summarizer, for example to downgrade severity, tell the analyst to close the alert, or smuggle a link
- Controls:
  - severity, score, confidence and playbook are computed by deterministic code; the model has no write path to them
  - incident text is sanitized (invisible characters removed, angle brackets neutralized, length capped) and placed in a delimited untrusted data block
  - model output is validated: no URLs, markdown or HTML, no invisible characters, length cap, and no claim of a severity that differs from the computed one
  - any rejection, timeout or backend error falls back to the deterministic summary
- Residual risk: a model can still produce a misleading but policy-conformant sentence. Analysts must treat `llm_summary` as a convenience, not as evidence. `analyst_summary` and `reasoning` stay authoritative.

3. Data leakage through metrics
- Threat: sensitive data in telemetry endpoint
- Control: metrics include only counters; no raw incident text

4. Availability pressure
- Threat: burst traffic overwhelms service; slow LLM backend ties up handler threads
- Control: lightweight deterministic core; bounded LLM timeout and response size; deterministic fallback; future rate limiting in ingress

5. Incident data leaving the trust boundary
- Threat: a remote LLM provider receives sensitive incident text
- Control: LLM is off by default; local Ollama is the default backend; remote use is an explicit choice (`--llm-provider openai --llm-url ...`); only http/https URLs are accepted; the API key comes from the environment and is excluded from `repr`

6. Exfiltration through model output
- Threat: output carries links or markdown images that leak data when rendered by a downstream UI
- Control: output policy rejects URLs and markup before the summary is stored or returned

## Residual risk

- In-memory telemetry is not durable.
- The output policy is heuristic. It blocks known bad shapes, not every misleading statement.
- Dataset bias can degrade severity calibration.
