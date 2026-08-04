# Enterprise capacity and SIEM safety

THOS is a query and investigation system, not a replacement telemetry data
lake. At 2,000 EPS a SIEM receives about 172.8 million events per day; at
8,000 EPS it receives about 691.2 million. Those events must remain indexed,
retained, and searched by the SIEM. THOS sends targeted read-only queries and
retrieves bounded evidence sets.

## What scales automatically

With **Configurations → General → Automatic hardware capacity** enabled, THOS
detects CPU affinity/quota and memory inside each container cgroup. It selects
one of four internal profiles and sizes new internal work accordingly:

| Profile | Visible minimum | Internal worker lanes | Forensic lanes | Risk lanes | PostgreSQL pool |
|---|---:|---:|---:|---:|---:|
| Compact | below 4 CPU or 8 GB | 1 | 1 | 1 | 4 |
| Balanced | 4 CPU and 8 GB | 2 | 2 | 1 | 8 |
| Capable | 8 CPU and 16 GB | 4 | 4 | 2 | 12 |
| Enterprise | 16 CPU and 32 GB | 8 | 8 | 4 | 20 |

This affects database connection capacity, forensic hashing/tool execution,
risk-analysis batches, and scheduled detection/file-scan lanes. Model routing
continues to use the separately configured Ollama/GPU memory budget because a
gateway container cannot safely infer memory belonging to a remote inference
worker.

Docker or Kubernetes resource assignments remain the hard deployment
boundary. Changing a container CPU/memory allocation requires recreating that
container; THOS then detects the new allocation at startup. No source-code
change or Codex access is required.

## SIEM limits never auto-increase

A more powerful THOS host says nothing about the capacity of the production
SIEM. Configure the following under **Configurations → General → SIEM retrieval
safety budgets**:

- default maximum returned rows per query;
- default concurrent requests per SIEM;
- queue timeout;
- optional Wazuh, Elasticsearch, Splunk, QRadar, or LogRhythm overrides.

The MCP fetch boundary enforces these values for every caller. Log Search,
hypothesis hunts, follow-up queries, anomaly monitoring, and scheduled
detections cannot bypass the ceiling. A request above the row limit is clamped
and reports the requested and applied values. Concurrent work waits in a
bounded queue and fails clearly when the queue timeout expires.

Recommended starting limits for a production change window are 250–500 rows
and one or two concurrent requests per SIEM. Increase them only after measuring
SIEM p95 query latency, search queues, rejection counts, and analyst evidence
coverage.

## High-EPS anomaly monitoring

Do not build an activity baseline from a newest-N sample. If a broad anomaly
window has more hits than the configured row budget, THOS pauses statistical
scoring and displays a sampling-limit warning instead of creating misleading
leads. For high-volume deployments, point anomaly monitoring at a scoped alert
index/data view whose 15-minute window fits the budget, or provide a
source-native aggregation query that returns entity counts rather than raw
events.

Targeted hypothesis and detection queries continue to work because filtering
and correlation execute in the SIEM before bounded matching evidence is
returned.

## Production deployment checklist

1. Allocate CPU and memory to each container in `.env` or the Kubernetes
   workload specification before deployment.
2. Keep Ollama on a dedicated GPU worker when scheduled and interactive model
   workloads must run concurrently.
3. Use a dedicated read-only SIEM service account and a scoped index/data view.
4. Start with 250–500 rows and concurrency 1–2 per SIEM.
5. Verify the detected capacity profile in Configurations after startup.
6. Run a representative targeted hunt and review returned-row counts, SIEM p95
   latency, queue depth, and rejected searches.
7. Increase SIEM limits gradually; do not size them from EPS alone.
8. Back up `data/runtime/config.json`, PostgreSQL, reports, and retained
   evidence through the organization’s approved secret-aware process.

The current Compose topology deliberately admits one governed hypothesis hunt
at a time and runs one scheduler owner. Do not add `chat-ui` or `orchestrator`
replicas without external leader election and distributed hunt admission.
Vertical resource scaling is automatic within the limits above; horizontal
control-plane scaling is a separate deployment architecture.
