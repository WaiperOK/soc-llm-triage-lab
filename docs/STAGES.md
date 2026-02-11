# Stages - soc-llm-triage-lab

## Stage 0 - Discovery and Threat Model
- Define stakeholders, data contracts, abuse cases, and SLAs/SLOs.
- Document trust boundaries and principal failure scenarios.
- Agree on compliance constraints (PII, audit, retention).

## Stage 1 - Vertical Slice (Implemented)
- Implement one end-to-end flow with deterministic behavior.
- Include tests for core decision logic.
- Add CI to validate quality gates on every change.

## Stage 2 - Production Readiness
- Add persistent storage and migration strategy.
- Add distributed tracing, metrics, structured logging.
- Add authn/authz, rate limiting, and policy enforcement.

## Stage 3 - Scale and Reliability
- Horizontal scaling and queue/backpressure design.
- Idempotency and replay-safe processing.
- Multi-region strategy and failure-domain isolation.

## Stage 4 - Governance and Platformization
- Org-wide standards (lint, release policy, security baseline).
- Golden paths/templates for new services.
- Operational playbooks and formal incident drills.
