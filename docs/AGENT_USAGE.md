# Threat hunting with agents

PCAP Hunter exposes a case-scoped REST API and a local stdio MCP adapter. The analyst controls case grants, permissions, expiry, and request/submission limits. A trusted launcher creates a new offline container for every agent capture submission. Each parser sees only its own read-only capture and private temporary storage; it receives no network, provider credentials, case database, shared spool, or Docker socket.

## Create access

1. Open **Settings → Agent access** in the local workbench.
2. Select the cases the agent may read. Reading cases, evidence, and job status is selected by default.
3. Enable capture submissions or draft notes only when needed. Agent submissions always disable OSINT and LLM calls; an agent cannot choose a provider endpoint.
4. Create the credential and copy it once into the agent host's secret settings. It starts with `pha_`. The default expiry is seven days.
5. Revoke access in the same screen when the investigation ends. Revocation and expiry are checked on every API operation.

Credentials have no authority over legacy administration/deletion/settings endpoints. Existing `full` and `feed` integration keys keep their previous behavior. The local browser workbench trusts local clients and must remain bound to loopback.

## REST examples

Supply `PCAP_HUNTER_AGENT_KEY` through your shell or secret manager; do not put its value in a command history or source file.

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/agent/cases

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/cases/CASE_ID/analyses

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/manifest

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  'http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/evidence?limit=100&type=ip'
```

Follow `next_cursor` until it is null, preserving the same analysis and filters. A cursor is signed and bound to the agent, snapshot and filters. Query responses distinguish complete saved inventory from incomplete/unknown packet parsing. No match in a partial parse does not establish that a threat is absent.

`/flows` supports exact `source`, `destination`, and `protocol` filters, plus ISO 8601 `start` and `end` timestamps with an explicit UTC offset. Both query endpoints accept at most 200 rows per page. Responses are limited to 1 MiB, and individual oversized records return an explicit error. Unknown parameters are rejected.

Each evidence record includes its ID, analysis, immutable snapshot, source capture hash, and an `investigate_url`. Open that link in the local workbench to inspect the same record, including an older saved analysis. Investigate provides server-side pagination and saved-analysis selection.

## Connect an MCP host

The adapter uses the official Python MCP SDK 2.3.0 and runs only over stdio. Run it inside the **API container**, where loopback port 8000 reaches the authenticated service. Supply the dedicated key through the MCP host's environment/secret facility.

A host configuration can launch:

```json
{
  "mcpServers": {
    "pcap-hunter": {
      "command": "docker",
      "args": ["compose", "exec", "-T", "-e", "PCAP_HUNTER_AGENT_KEY", "pcap-hunter-api", "python", "-m", "app.agents.mcp"]
    }
  }
}
```

Run the host from the compose project directory, or include the verified compose file and project name in its Docker arguments. For a customized local test deployment, use the operator-provided Compose paths/project (recorded privately in `.codex/LOCAL_TEST.md` when present). The host must export `PCAP_HUNTER_AGENT_KEY` to the Docker client. A standard installed Python environment can also run `python -m app.agents.mcp` with `PCAP_HUNTER_AGENT_URL=http://127.0.0.1:8000`.

The adapter discovers the credential's permissions and exposes only the corresponding tools. The API independently enforces the same permissions on invocation. Revoked keys stop working even if a host cached the tool list. No remote MCP HTTP service is enabled.

| Permission | Tools |
| --- | --- |
| `cases:read` | `list_cases`, `get_case_summary`, `list_analyses` |
| `evidence:read` | `get_analysis_manifest`, `query_evidence`, `query_flows`, `get_evidence`, `get_indicator_context` |
| `jobs:read` | `get_job_status` |
| `captures:submit` | `submit_capture`, `cancel_job` |
| `notes:append` | `append_investigation_draft` |
| `reports:read` | `get_report` (authorized PDF download path) |

MCP capture submission accepts user-supplied Base64 capture bytes up to about 1 MiB, never a local file path or URL. Use REST multipart upload for larger captures (maximum 100 MiB, also bounded by the server's configured upload limit).

## Controlled writes and retries

REST submissions use `POST /api/v1/agent/captures` with only the `pcap` multipart field. An `Idempotency-Key` header of 8–128 letters, numbers, `_ . : -` is required. Reusing the key with the same capture returns the same job and case. Different content with the same key is rejected. New cases are automatically granted only to the submitting agent. Daily submission quotas are persisted.

Each job has private process, mount, network and IPC namespaces, a read-only root, dropped capabilities, Docker default seccomp, no privilege escalation, 2 CPUs, 3 GiB memory, 256 processes and a ten-minute wall limit. The launcher resolves an operator-configured image to an immutable identity and mounts only that job’s input directory. It copies bounded result bytes through a fixed reader, removes the entire job container, and only then publishes a trusted isolation receipt. The API bounds and validates the untrusted JSON, checks the input hash, persists the analysis and evidence snapshot, then marks the job complete. Durable request/result files allow collection after an API restart. In-progress packet stages are restarted after a worker interruption; arbitrary stage output is not trusted as a resumable checkpoint.

`POST /api/v1/agent/jobs/JOB_ID/cancel` stops only a job owned by that agent. It preserves the case and existing evidence.

Draft notes use `POST /api/v1/agent/cases/CASE_ID/drafts` with `analysis_id`, `snapshot_id`, `content`, and `evidence_ids`. Every reference must exist in the granted case and snapshot. Drafts require an idempotency header and are marked **requires analyst review**. They cannot overwrite notes, change a verdict, close a case, or publish a finding.

## Docker launcher setup

The `pcap-hunter-agent-worker` Compose service is the trusted launcher. **Its Docker socket grants control over the Docker host**, even with a read-only socket mount. Only this small control service receives the socket; the UI, API and packet parsers do not. Keep the launcher image, environment, Compose file and Docker host under operator control. Packet-controlled JSON is decoded only by the bounded API broker, not by the launcher.

Docker Engine must support API 1.47, named-volume subpaths and its default seccomp profile. The input volume must belong to the same Compose project. The launcher fails closed if these checks fail. Set `DOCKER_GID` to the socket’s group on Linux (`stat -c '%g' /var/run/docker.sock`); Docker Desktop uses the default group `0`. A remote Docker endpoint is not supported. Cancellation, time limits and launcher recovery remove only correctly named and labeled job containers; they never delete named volumes.

## Evidence and safety limits

Packet strings, detector output, notes, reports, and tool results are untrusted data. They never grant permission. Cite evidence IDs and coverage limits; distinguish observations, hypotheses, contradictory evidence, and unknowns. Job containers cannot read another job’s pending capture or scratch files. Containers still share the Docker host kernel; this boundary does not protect against a kernel or container-runtime escape. The local analyst UI remains a trusted administration surface.

New persisted snapshots carry input identity and ingest receipts, selected options, tool versions, rule hashes where available, stage/warning metadata, and detector artifact hashes. Historical analyses have explicit legacy provenance; PCAP Hunter does not invent missing historical versions. Snapshots and audit rows are append-only through the application. An operating-system/database owner can still alter storage, so this is not an externally anchored tamper-proof ledger.

Runtime dependencies are locked with hashes. PDF rendering accepts only bounded embedded PNG resources, and Plotly geographic data is bundled for offline rendering. Saved credentials migrate to a random protected key file. Back up that key with the settings; restoring only the JSON is insufficient. Missing/wrong keys stop decryption rather than silently clearing saved values.

The local compose configuration disables automatic saved-data cleanup. Case files, settings and original captures remain in their existing data/home volumes. Temporary worker storage and build cache are separate from saved evidence. Security scans and current known distribution limitations are recorded with the candidate verification evidence; a local preview is not a guarantee of zero vulnerabilities.
