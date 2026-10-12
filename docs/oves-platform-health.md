# OVES platform health

A 60-second collector on the billing box that watches the OVES platform so
problems show up on the admin dashboard (Admin > Dashboard > OVES platform
health) and in the admin inbox before anyone reports them.

Code: `app/services/oves_health/`. API: `GET /api/admin/oves-health`,
`GET /api/admin/oves-health/history?hours=1..336[&probe=<id>]` (admin only).
Scheduler job `oves_health_snapshot` (main.py), table `oves_health_snapshots`
(14 days of per-minute metrics; the full panel payload is kept 3 hours).

## What it watches

| Area | Source | How |
|---|---|---|
| Code generation | prod `thing-microservice`, `-make`, `-use` pod logs | `Request to generate* took N ms` = one success + latency (the interceptor logs on success only); `ERROR [CodeEvent*/Codegen*]` = failure, classified user vs platform. Guard rejections never reach these logs, so failures are a floor. |
| Elasticsearch indexing | same logs | `Error indexing codeevent` count (code search completeness) |
| MongoDB rs0 | login probe, `/health/db` on 7 services, app-log "not primary" errors, EC2 status + CPU credits (AWS) | rs0 is private; no member state from outside |
| Clusters (prod, AWS dev, Tencent) | Kubernetes API | named key services with pod state (shadow path first on prod), workloads, restarts/OOM/crash loops, machines summary, node CPU/mem/disk via in-cluster Prometheus |
| Ingress | prod ingress-nginx access logs | per-service requests, 5xx, p95 |
| Dependencies | black-box probes from Hetzner | OVES prod, AWS dev services prod relies on, Tencent (MQTT CONNECT, wvapp, ABS, DIRAC, Mongo hello), third parties, Bitwave's own (M-Pesa, AWS transit) |
| Exposure | TCP connect | database ports that must NOT answer from the internet |
| GraphQL errors (Apollo) | GraphOS Platform API, every subgraph's own key | Studio's Insights numbers: requests, errors, error rate per operation, error groups with messages. Catches errors returned inside HTTP 200 that never reach the logs (E11000 duplicate codes, 30 s MongoDB server-selection timeouts, schema mismatches). Code values in messages are masked. |

Alerts go to every admin's inbox (deduped, with a RECOVERED notice when they
clear); critical ones also SMS `OPS_ALERT_SMS_PHONE`. Rules: `rules.py`.

## Turning it on

1. Per cluster, apply the read-only identity (it can list and read logs, never change anything):
   ```bash
   kubectl --context oves-prod apply -f deploy/oves-health/rbac.yaml
   kubectl --context oves-dev  apply -f deploy/oves-health/rbac.yaml
   ```
   Tencent TKE: the same file with the Tencent kubeconfig.
2. Read each cluster's token, server and CA into `.env.hetzner` on the box (never into git):
   ```bash
   kubectl --context oves-prod -n default get secret bitwave-health-reader-token -o jsonpath='{.data.token}' | base64 -d
   kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="<cluster arn>")].cluster.server}'
   kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="<cluster arn>")].cluster.certificate-authority-data}'
   ```
3. Optional: a read-only IAM user in 734862689453 for the MongoDB hosts (`cloudwatch:GetMetricStatistics`,
   `ec2:DescribeInstanceStatus`, `ec2:DescribeInstanceCreditSpecifications`).
4. Optional: `OVES_APOLLO_GRAPH_KEYS=Graph-Id=service:Graph-Id:...,...` (each subgraph's
   `APOLLO_KEY` from its deployment-charts values) for the code-generation numbers and the Errors
   tab. Only platform errors alert; callers' own mistakes (bad credentials, rate limit, unknown
   item) are shown but never alert.
5. Set `OVES_HEALTH_ENABLED=true` and redeploy. The first snapshot appears within a minute.

## Known findings when this was built (2026-10-12)

- Four database ports answer from the internet: prod `data-services` MongoDB LB :27017, prod Redis
  :6379, Tencent dev MongoDB rs0 :27017, AWS dev MongoDB EC2 :27017.
- ~40 % of generated codes fail Elasticsearch indexing (`Error indexing codeevent`).
- Code generation p50 is ~2.4 s, p95 ~3.4-3.7 s.
- All three rs0 members are T2 Unlimited now; 10.0.1.129 runs ~61 % CPU at 0 banked credits
  (not throttled, billed surplus).
- Self-hosted dev Odoo (`odoo.omnivoltaic.com`) returns 502.
- Apollo, 24 h: Event-Microservice-Prod fails 99 % of requests with `Cannot query field
  "microserviceEvents_2024" on type "Mutation"` (a client still calls a removed mutation);
  GenerateDaysCode has E11000 duplicate-code collisions; GenerateFreeCodeSafe hit 30 s MongoDB
  server-selection timeouts in the past week. The log-based count misses ~1/3 of code requests.
