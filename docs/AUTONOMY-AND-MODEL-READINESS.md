# THOS autonomy and model-readiness review

Review date: 2026-07-30

## Result

THOS is an agent-directed, evidence-gated hunting and forensic platform, but it
is not yet a fully autonomous, certified cybersecurity expert.

The agent model currently owns:

- investigation-branch planning and iterative query refinement;
- broadening, tightening, lookback, source, and stopping decisions within
  configured resource bounds;
- evidence selection, telemetry-coverage assessment, hunt reasoning, risk
  analysis, schedule prioritization, forensic tool selection, and forensic
  interpretation.

Deterministic components correctly retain ownership of authentication,
authorization, session validation, path and command allowlists, query-schema
validation, resource limits, citation validation, evidence integrity, and the
zero-evidence gate. These are safety controls, not threat-hunting judgments,
and should not be delegated to a probabilistic model.

## Remaining autonomy gaps

1. The default local models are general-purpose base models. No
   cybersecurity-specific adapter or passing certification is shipped.
2. The current retrieval benchmark contains only ten cases. It tests source
   recall, not end-to-end analyst competence, verdict calibration, or
   multi-source investigation quality.
3. The governed knowledge corpus is narrow: ATT&CK Enterprise, CISA KEV, a
   small NIST set, and the local community detection-rule corpus. It does not
   yet cover cloud-provider audit semantics, identity-provider semantics,
   protocol field dictionaries, malware behavior, defensive
   countermeasures, vulnerability taxonomies, or organization baselines in
   comparable depth.
4. Hunt reasoning receives only a bounded sample of raw records plus
   aggregate facts. A selected sample can still omit a decisive relationship
   unless entity/temporal correlation is materialized before reasoning.
5. Telemetry normalization is vendor-specific and partly fingerprint-based.
   New integrations require validated schemas, field mappings, and realistic
   connector tests before an agent can hunt them reliably.
6. THOS now persists deterministic user, host, source-IP, and user-to-host
   activity windows, but it does not yet provide a complete cross-source graph
   linking processes, sessions, files, indicators, and prior investigations.
7. The initial measured baseline covers robust activity spikes and new
   user-to-host relationships. Peer-group comparison, seasonality, longer-term
   drift, and richer behavioral sequences are not yet implemented.
8. Endpoint collection and network session/packet pivots are not yet
   first-class agent tools. A SIEM can only return what it received.
9. Static fallback hypotheses and a generated required-gap catalog still
   contain prewritten hunt content and Wazuh-specific rule-count statements.
   They are catalog data, not live model decisions, but they can become stale
   and should be replaced by versioned, provenance-bearing generated content.
10. Model failure currently degrades some planning stages to an empty plan or
    incomplete coverage record. This is safe, but it is not autonomous
    completion.
11. Fine-tuning preparation exists, but training, adapter import, shadow
    evaluation, promotion, rollback, and drift monitoring are not an
    end-to-end automated lifecycle.
12. There is no evidence that the full connector set has passed enterprise
    scale, fault-injection, data-loss, schema-drift, and long-duration soak
    tests against real vendor systems.

## Model release policy

`services/evaluation/cybersecurity_capability.py` now fails model promotion
unless a frozen evaluation provides sufficient domain and scenario coverage,
claim-level safety metrics, immutable snapshot identifiers, and explicit SME
approval. The policy manifest is
`data/evals/cybersecurity_capability_requirements.json`.

A passing result is permission to canary a model, not proof of universal
competence. Production dispositions remain:

- supported by cited evidence;
- partially supported;
- refuted within measured coverage;
- inconclusive due to missing or conflicting evidence.

Attribution, intent, and impact must never be inferred beyond cited telemetry
and governed reference knowledge.

## Recommended next integration order

1. Endpoint hunt and collection API.
2. Passive network metadata and network alert telemetry.
3. Full-packet/session pivot API for selected high-value evidence.
4. Threat-intelligence graph and indicator-sharing API.
5. Cross-source entity and temporal graph.
6. Super-timeline generation and collaborative timeline analysis.
7. Runtime container/Linux telemetry.
8. Modern pattern-matching engine migration and expanded static malware
   analysis.
9. Controlled adversary-emulation telemetry for regression testing.
10. Dedicated model evaluation, red-team, fine-tuning, registry, canary, and
    rollback pipeline.
