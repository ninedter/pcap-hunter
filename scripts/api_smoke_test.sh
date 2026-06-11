#!/usr/bin/env bash
# scripts/api_smoke_test.sh — end-to-end smoke test for the integrations API.
# Usage:
#   PCAP_HUNTER_API_KEY=... PCAP_HUNTER_FEED_KEY=... ./scripts/api_smoke_test.sh
set -euo pipefail

API="${API:-http://127.0.0.1:8000}"
KEY="${PCAP_HUNTER_API_KEY:?must be set}"
FEED="${PCAP_HUNTER_FEED_KEY:-$KEY}"
FIXTURE="${FIXTURE:-tests/fixtures/tiny.pcap}"

if [[ ! -f "$FIXTURE" ]]; then
    echo "fixture not found: $FIXTURE" >&2
    exit 1
fi

echo "=== /healthz ==="
curl -fsS "$API/healthz" | tee /dev/stderr
echo

echo "=== /readyz ==="
curl -fsS "$API/readyz" | tee /dev/stderr
echo

echo "=== POST /api/v1/pcaps ==="
RESP=$(curl -fsS -X POST "$API/api/v1/pcaps" \
    -H "Authorization: Bearer $KEY" \
    -F "pcap=@$FIXTURE" \
    -F "name=smoke" \
    -F "osint_enabled=false" \
    -F "llm_enabled=false")
echo "$RESP"
JOB_ID=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['job_id'])")
CASE_ID=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['case_id'])")
echo "job_id=$JOB_ID case_id=$CASE_ID"

echo "=== Polling until done (max 120s) ==="
for _ in $(seq 1 60); do
    STATUS=$(curl -fsS "$API/api/v1/jobs/$JOB_ID" \
        -H "Authorization: Bearer $KEY" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
    echo "  status=$STATUS"
    if [[ "$STATUS" == "done" || "$STATUS" == "failed" ]]; then
        break
    fi
    sleep 2
done
[[ "$STATUS" == "done" ]] || { echo "job did not finish: $STATUS"; exit 1; }

echo "=== GET /api/v1/jobs/$JOB_ID/result ==="
curl -fsS "$API/api/v1/jobs/$JOB_ID/result" \
    -H "Authorization: Bearer $KEY" | python3 -m json.tool

echo "=== analysis persisted? ==="
AID=$(curl -fsS "$API/api/v1/jobs/$JOB_ID/result" -H "Authorization: Bearer $KEY" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis_id'] or '')")
[[ -n "$AID" ]] || { echo "analysis_id missing — persistence broken"; exit 1; }

echo "=== case shows the analysis ==="
N=$(curl -fsS "$API/api/v1/cases/$CASE_ID" -H "Authorization: Bearer $KEY" \
    | python3 -c "import json,sys; print(len(json.load(sys.stdin)['analyses']))")
[[ "$N" -ge 1 ]] || { echo "case has no analyses"; exit 1; }

echo "=== report.pdf renders on demand ==="
PDF_CODE=$(curl -sS -o /tmp/smoke_report.pdf -w "%{http_code}" \
    "$API/api/v1/cases/$CASE_ID/report.pdf" -H "Authorization: Bearer $KEY")
if [[ "$PDF_CODE" == "200" ]]; then
    head -c4 /tmp/smoke_report.pdf | grep -q "%PDF" || { echo "not a pdf"; exit 1; }
elif [[ "$PDF_CODE" != "503" ]]; then
    echo "report.pdf unexpected status: $PDF_CODE"; exit 1
fi
rm -f /tmp/smoke_report.pdf

echo "=== feed serves this case's iocs ==="
curl -fsS "$API/api/v1/iocs.json?case_id=$CASE_ID" -H "Authorization: Bearer $FEED" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print('feed count:', d['count'])"

echo "=== GET /api/v1/iocs.json ==="
curl -fsS "$API/api/v1/iocs.json" \
    -H "Authorization: Bearer $FEED" | python3 -m json.tool | head -30

echo "=== DELETE /api/v1/cases/$CASE_ID ==="
curl -fsS -X DELETE "$API/api/v1/cases/$CASE_ID" \
    -H "Authorization: Bearer $KEY" -o /dev/null -w "%{http_code}\n"

echo "=== feed empty for deleted case (cascade) ==="
curl -fsS "$API/api/v1/iocs.json?case_id=$CASE_ID" -H "Authorization: Bearer $FEED" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['count'] == 0, f'orphans: {d}'; print('clean')"

echo "✓ smoke test passed"
