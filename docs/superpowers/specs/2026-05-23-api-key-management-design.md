# API Key Management System — Design Spec

**Date:** 2026-05-23
**Status:** Approved
**Branch:** feat/integrations-api

## Overview

Replace the current single-env-var API key approach with a DB-backed multi-key
store. Adds CRUD API endpoints, per-key usage tracking, in-memory rate limiting
with periodic DB flush, key expiration/revocation, and a Streamlit admin tab for
visual management. Env-var keys remain as bootstrap/fallback.

## Approach: Hybrid (C)

- SHA-256 hashed keys in SQLite `api_keys` table
- In-memory sliding-window rate limiter (fast path, zero DB writes per request)
- Background periodic flush (60s) of usage counters to `api_key_usage` table
- On restart, rate limiter starts clean (1-minute window, acceptable burst)
- Env-var keys checked first (constant-time compare, no DB hit)

## Data Model

### Table: `api_keys`

```sql
CREATE TABLE api_keys (
    id             TEXT PRIMARY KEY,
    key_hash       TEXT NOT NULL UNIQUE,
    key_prefix     TEXT NOT NULL,
    name           TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT 'feed',
    description    TEXT DEFAULT '',
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at     TIMESTAMP,
    revoked_at     TIMESTAMP,
    last_used_at   TIMESTAMP,
    total_requests INTEGER DEFAULT 0,
    rate_limit_rpm INTEGER,
    source         TEXT DEFAULT 'admin'
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
```

### Table: `api_key_usage`

```sql
CREATE TABLE api_key_usage (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id   TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    date     TEXT NOT NULL,
    requests INTEGER DEFAULT 0,
    UNIQUE(key_id, date)
);
CREATE INDEX idx_usage_key_date ON api_key_usage(key_id, date);
```

### Dataclass: `APIKey`

```python
@dataclass
class APIKey:
    id: str = ""
    key_hash: str = ""
    key_prefix: str = ""
    name: str = ""
    scope: Scope = Scope.FEED
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    total_requests: int = 0
    rate_limit_rpm: int | None = None
    source: str = "admin"

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and datetime.now() > self.expires_at:
            return False
        return True
```

## Key Lifecycle

### Key Format

`phk_` + 32 random hex chars = 36 chars total.
Example: `phk_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4`

### Generation Flow

1. Generate 16 random bytes via `secrets.token_hex(16)`
2. Prepend `phk_` prefix
3. SHA-256 hash the full key string
4. Store hash in `api_keys.key_hash`, first 8 chars in `key_prefix`
5. Return raw key **once** in creation response
6. Key cannot be retrieved after creation

### Expiration

- Checked on every auth attempt
- Expired keys return 401 with code `key_expired`
- No background cleanup — simply rejected on use

### Revocation

- Sets `revoked_at` timestamp (soft delete)
- Revoked keys return 401 with code `key_revoked`
- Immediate effect on next request

## Auth Flow

```
Request: "Bearer <token>"
  |
  +-- Try env-var keys first (constant-time compare, no DB)
  |     +-- Matches PCAP_HUNTER_API_KEY -> Scope.FULL, key_name="env:main"
  |     +-- Matches PCAP_HUNTER_FEED_KEY -> Scope.FEED, key_name="env:feed"
  |
  +-- No env match -> SHA-256(token) -> lookup in api_keys
  |     +-- Found + active -> granted scope, key_name=row.name
  |     +-- Found + revoked -> 401 "key_revoked"
  |     +-- Found + expired -> 401 "key_expired"
  |     +-- Not found -> 401 "invalid_key"
  |
  +-- Rate limit check (in-memory sliding window)
  |     +-- Under limit -> proceed
  |     +-- Over limit -> 429 + Retry-After header
  |
  +-- Record usage (in-memory counter, flushed every 60s)
```

Env-var keys are never rate-limited and never expire.

## Rate Limiting

### In-Memory Sliding Window

```python
class RateLimiter:
    _windows: dict[str, deque[float]]  # key_id -> timestamps

    def check(self, key_id: str, limit_rpm: int | None) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        if limit_rpm is None:
            return True, 0
        now = time.monotonic()
        window = self._windows.setdefault(key_id, deque())
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= limit_rpm:
            retry_after = int(window[0] + 60 - now) + 1
            return False, retry_after
        window.append(now)
        return True, 0
```

- Env-var keys bypass rate limiting entirely
- 429 response includes `Retry-After` header

## Usage Tracking

### In-Memory Accumulator

```python
class UsageTracker:
    _counts: dict[str, int]       # key_id -> count since last flush
    _last_used: dict[str, float]  # key_id -> monotonic timestamp

    def record(self, key_id: str) -> None:
        self._counts[key_id] = self._counts.get(key_id, 0) + 1
        self._last_used[key_id] = time.time()

    def flush(self, repo: KeyRepository) -> None:
        today = date.today().isoformat()
        for key_id, count in self._counts.items():
            repo.increment_usage(key_id, today, count)
            repo.touch_key_last_used(key_id, self._last_used.get(key_id))
        self._counts.clear()
        self._last_used.clear()
```

- Flush runs every 60 seconds via asyncio task in FastAPI lifespan
- Final flush on shutdown to avoid losing last minute's data
- `api_keys.total_requests` incremented atomically during flush

## API Endpoints

Router: `app/api/routers/admin.py` — all require `Scope.FULL`.

| Method  | Path                               | Description                     |
|---------|------------------------------------|---------------------------------|
| POST    | /api/v1/admin/keys                 | Create key (returns raw key)    |
| GET     | /api/v1/admin/keys                 | List all keys (metadata only)   |
| GET     | /api/v1/admin/keys/{key_id}        | Key details + recent usage      |
| PATCH   | /api/v1/admin/keys/{key_id}        | Update name/scope/rate/expiry   |
| DELETE  | /api/v1/admin/keys/{key_id}        | Revoke key (soft delete)        |
| GET     | /api/v1/admin/keys/{key_id}/usage  | Daily usage for last N days     |
| GET     | /api/v1/admin/usage/summary        | Aggregate usage across all keys |

### Create Key Request

```json
{
  "name": "Splunk production",
  "scope": "feed",
  "description": "IOC feed for Splunk HQ",
  "rate_limit_rpm": 60,
  "expires_in_days": 90
}
```

### Create Key Response (201)

```json
{
  "id": "k_a1b2c3d4e5f6",
  "key": "phk_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "name": "Splunk production",
  "prefix": "phk_a1b2",
  "scope": "feed",
  "expires_at": "2026-08-21T00:00:00",
  "rate_limit_rpm": 60
}
```

The `key` field appears ONLY in this response.

## Streamlit Admin Tab

New module: `app/ui/api_keys_tab.py` with `render_api_keys_tab()`.

### Layout

**Section A — Dashboard Metrics (top)**
- Three `st.metric()` cards: Active Keys | Requests Today | Keys Expiring ≤7d
- Bar chart: daily request volume (last 30 days) per key

**Section B — Key List (middle)**
- `st.dataframe()` with columns: Name, Prefix, Scope, Status, Created,
  Expires, Last Used, Requests, Rate Limit
- Status values: Active (green), Expiring Soon (yellow), Expired (red),
  Revoked (grey)
- Expandable rows for edit/revoke actions

**Section C — Create Key (bottom)**
- `st.form()` with fields: name, scope dropdown, description, rate limit
  (optional number input), expiration (date input or "Never" checkbox)
- On submit: generates key, shows in `st.code()` block with copy warning
- Warning: "This key will not be shown again. Copy it now."

### Env-Var Keys Display

- Shown in a separate section at the top of the key list
- Labelled "Environment Keys (read-only)"
- Cannot be edited or revoked from the UI
- Shows scope and whether set (without revealing the actual value)

## Backward Compatibility

- `PCAP_HUNTER_API_KEY` and `PCAP_HUNTER_FEED_KEY` env vars continue to work
- Checked first in auth flow (fast path)
- No rate limit, no expiration, not revocable from UI
- `NoKeysConfiguredError` relaxed: raised only if no env keys AND no DB keys
- Existing tests for env-var auth remain unchanged

## New Files

```
app/api/key_models.py          - APIKey dataclass, request/response schemas
app/api/key_repository.py      - KeyRepository class (CRUD, usage, schema)
app/api/key_auth.py            - DB-aware auth, RateLimiter, UsageTracker
app/api/routers/admin.py       - Admin key management endpoints
app/ui/api_keys_tab.py         - Streamlit admin tab

tests/api/test_key_repository.py
tests/api/test_key_auth.py
tests/api/test_admin_api.py
tests/api/test_rate_limiter.py
tests/ui/test_api_keys_tab.py
```

## Modified Files

```
app/api/auth.py        - Delegate to key_auth for DB lookup
app/api/settings.py    - Relax NoKeysConfiguredError
app/api/app.py         - Wire admin router, usage flush task, key identity
app/api/deps.py        - Add get_key_repo(), updated auth deps
app/main.py            - Add API Keys tab
```

## Testing Strategy

- KeyRepository: CRUD, expired/revoked queries, usage increment, schema init
- RateLimiter: capacity check, window expiry, unlimited keys, concurrent access
- Auth flow: env-var fallback -> DB key -> expired -> revoked -> rate-limited -> 429
- Admin endpoints: create returns key once, list hides raw keys, revoke is soft-delete
- Streamlit tab: renders without crash, create/revoke flows
- Backward compat: existing env-var auth tests still pass unchanged
