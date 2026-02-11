# Threat Model

## Assets

- triage input events
- playbook corpus
- triage outputs and confidence labels
- telemetry stream

## Threats and controls

1. Malformed payload crash
- Threat: invalid JSON, missing fields
- Control: strict decode + validation with 400 response

2. Prompt-like injection in incident text
- Threat: attacker-controlled text influences triage output format
- Control: deterministic scoring/retrieval pipeline (no dynamic code execution)

3. Data leakage through metrics
- Threat: sensitive data in telemetry endpoint
- Control: metrics include only counters; no raw incident text

4. Availability pressure
- Threat: burst traffic overwhelms service
- Control: lightweight deterministic handlers; future add rate limiting in ingress

## Residual risk

- In-memory telemetry is not durable.
- Dataset bias can degrade severity calibration.
