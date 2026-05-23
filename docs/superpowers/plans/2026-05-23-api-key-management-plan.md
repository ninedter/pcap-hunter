# API Key Management — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-05-23-api-key-management-design.md`
**Branch:** feat/integrations-api

## Milestone 1: Data Layer (Tasks 1-5)

### Task 1: Key Models
**Files:** `app/api/key_models.py` (create)
- `APIKey` dataclass with all fields from spec
- `is_active` property (checks revoked_at and expires_at)
- `to_dict()` method (excludes key_hash, includes computed `status` field)
- `Scope` import from existing `app/api/auth.py`

### Task 2: Key Repository — Schema & CRUD
**Files:** `app/api/key_repository.py` (create)
- `KeyRepository.__init__(db_path)` — creates `api_keys` and `api_key_usage` tables
- `create_key(name, scope, key_hash, key_prefix, ...) -> APIKey`
- `get_key_by_id(key_id) -> APIKey | None`
- `get_key_by_hash(key_hash) -> APIKey | None` (for auth lookup)
- `list_keys(include_revoked=False) -> list[APIKey]`
- `update_key(key_id, **fields) -> APIKey | None`
- `revoke_key(key_id) -> bool` (sets revoked_at)
- Same `_get_conn()` pattern as `CaseRepository`
- Uses same SQLite DB path pattern

### Task 3: Key Repository — Usage Methods
**Files:** `app/api/key_repository.py` (extend)
- `increment_usage(key_id, date_str, count)` — UPSERT into api_key_usage
- `touch_key_last_used(key_id, timestamp)` — updates last_used_at and total_requests
- `get_usage(key_id, days=30) -> list[dict]` — daily usage for a key
- `get_usage_summary(days=30) -> list[dict]` — aggregate across all keys
- `count_active_keys() -> int`
- `get_expiring_keys(within_days=7) -> list[APIKey]`

### Task 4: Key Repository Tests
**Files:** `tests/api/test_key_repository.py` (create)
- test_create_and_get_key
- test_get_key_by_hash
- test_list_keys_excludes_revoked
- test_revoke_key
- test_update_key_fields
- test_increment_usage_upsert
- test_get_usage_returns_daily_data
- test_get_expiring_keys
- test_schema_idempotent (init twice, no error)

### Task 5: Verify Task 1-4
- Run `make verify` — all tests pass, lint clean

## Milestone 2: Auth & Rate Limiting (Tasks 6-11)

### Task 6: Rate Limiter
**Files:** `app/api/rate_limiter.py` (create)
- `RateLimiter` class with `_windows: dict[str, deque[float]]`
- `check(key_id, limit_rpm) -> tuple[bool, int]` — returns (allowed, retry_after)
- Thread-safe (use threading.Lock for deque access)

### Task 7: Usage Tracker
**Files:** `app/api/usage_tracker.py` (create)
- `UsageTracker` class with `_counts: dict[str, int]`, `_last_used: dict[str, float]`
- `record(key_id)` — increment counter
- `flush(repo: KeyRepository)` — write to DB and clear
- Thread-safe (threading.Lock)

### Task 8: DB-Aware Auth
**Files:** `app/api/key_auth.py` (create)
- `check_bearer_with_db(authorization, settings, key_repo, required_scope) -> tuple[Scope, str, APIKey | None]`
  - Returns (granted_scope, key_name, api_key_or_none)
  - Tries env-var keys first (existing `_const_eq` logic)
  - Falls back to DB lookup via SHA-256 hash
  - Checks expired/revoked status
  - Raises ValueError for 401, PermissionError for 403

### Task 9: Update deps.py
**Files:** `app/api/deps.py` (modify)
- Add `get_key_repo() -> KeyRepository` with `lru_cache(maxsize=1)`
- Add `get_rate_limiter() -> RateLimiter` singleton
- Add `get_usage_tracker() -> UsageTracker` singleton
- Update `require_full_scope()` and `require_feed_scope()` to use `check_bearer_with_db`
- Rate limit check after auth succeeds — raise HTTPException(429) if over limit
- Call `usage_tracker.record(key_id)` on success

### Task 10: Rate Limiter & Auth Tests
**Files:** `tests/api/test_rate_limiter.py` (create), `tests/api/test_key_auth.py` (create)
- Rate limiter: test_allows_under_limit, test_blocks_over_limit, test_window_expires,
  test_unlimited_key, test_retry_after_calculation
- Auth: test_env_key_fallback, test_db_key_lookup, test_expired_key_rejected,
  test_revoked_key_rejected, test_scope_enforcement, test_rate_limited_returns_429

### Task 11: Verify Tasks 6-10
- Run `make verify` — all tests pass, lint clean

## Milestone 3: Admin API Endpoints (Tasks 12-17)

### Task 12: Key Generation Utility
**Files:** `app/api/key_models.py` (extend)
- `generate_api_key() -> tuple[str, str, str]` — returns (raw_key, key_hash, key_prefix)
- Uses `secrets.token_hex(16)`, SHA-256 for hash, first 8 chars for prefix
- Key format: `phk_` + 32 hex chars

### Task 13: Admin Router — Create & List
**Files:** `app/api/routers/admin.py` (create)
- `POST /api/v1/admin/keys` — validates input, generates key, stores, returns 201 with raw key
- `GET /api/v1/admin/keys` — returns list of keys (no raw key, no hash)
- Both require `Scope.FULL`
- Input validation: name required, 1-100 chars; scope must be 'full' or 'feed';
  rate_limit_rpm >= 1 if set; expires_in_days >= 1 if set

### Task 14: Admin Router — Get, Update, Delete
**Files:** `app/api/routers/admin.py` (extend)
- `GET /api/v1/admin/keys/{key_id}` — 404 if not found
- `PATCH /api/v1/admin/keys/{key_id}` — partial update (name, scope, description, rate_limit_rpm, expires_at)
- `DELETE /api/v1/admin/keys/{key_id}` — soft-revoke (sets revoked_at), 404 if not found

### Task 15: Admin Router — Usage Endpoints
**Files:** `app/api/routers/admin.py` (extend)
- `GET /api/v1/admin/keys/{key_id}/usage?days=30`
- `GET /api/v1/admin/usage/summary?days=30`

### Task 16: Wire Admin Router into App
**Files:** `app/api/app.py` (modify)
- Import and include admin router
- Add usage flush task to lifespan (every 60s, final flush on shutdown)
- Update `_identify_key()` to check DB keys for audit log

### Task 17: Admin Endpoint Tests & Verify
**Files:** `tests/api/test_admin_api.py` (create)
- test_create_key_returns_raw_key_once
- test_list_keys_hides_raw_key
- test_get_key_detail
- test_update_key_fields
- test_revoke_key_soft_delete
- test_usage_endpoint
- test_create_key_requires_full_scope
- test_create_key_validates_input
- Run `make verify`

## Milestone 4: Settings & Backward Compat (Tasks 18-20)

### Task 18: Relax NoKeysConfiguredError
**Files:** `app/api/settings.py` (modify)
- `from_env()` no longer raises if no env keys are set
- Instead, store `main_key=None, feed_key=None`
- New method: `has_any_auth(key_repo) -> bool` — checks env keys OR DB keys exist
- App startup in `create_app()` checks this and raises if neither source has keys

### Task 19: Update Existing Auth Tests
**Files:** `tests/api/test_auth.py` (modify if exists), other test files that mock settings
- Ensure existing env-var auth tests still pass unchanged
- Add test: DB key works when env keys are None
- Add test: env key takes precedence over DB key with same token (edge case)

### Task 20: Verify Backward Compat
- Run full `make verify` — all 650+ existing tests still pass
- Confirm env-var-only startup still works

## Milestone 5: Streamlit Admin Tab (Tasks 21-25)

### Task 21: API Keys Tab — Key List
**Files:** `app/ui/api_keys_tab.py` (create)
- `render_api_keys_tab()` — main entry point
- `_get_key_repo()` — session state singleton
- Key list as `st.dataframe()` with status badges
- Environment keys section (read-only display, shows if set without value)

### Task 22: API Keys Tab — Dashboard Metrics
**Files:** `app/ui/api_keys_tab.py` (extend)
- Three `st.metric()` cards in columns: Active Keys, Requests Today, Expiring Soon
- Bar chart of daily request volume (last 30 days) via `st.bar_chart()`

### Task 23: API Keys Tab — Create & Revoke
**Files:** `app/ui/api_keys_tab.py` (extend)
- Create key form with `st.form()`: name, scope, description, rate limit, expiration
- Generated key display in `st.code()` with warning banner
- Revoke button with `st.confirmation_dialog()` or manual confirm pattern

### Task 24: Wire Tab into Main
**Files:** `app/main.py` (modify)
- Import `render_api_keys_tab` from `app.ui.api_keys_tab`
- Add "API Keys" to the tab list in `make_tabs()`
- Tab appears after existing tabs

### Task 25: Tab Smoke Tests & Verify
**Files:** `tests/ui/test_api_keys_tab.py` (create)
- test_render_does_not_crash (mock repo, call render function)
- test_key_list_shows_keys
- Run `make verify`

## Milestone 6: Final Integration (Tasks 26-27)

### Task 26: End-to-End Flow Test
**Files:** `tests/api/test_key_e2e.py` (create)
- Full flow: create key via admin API -> use key to call /api/v1/iocs.json -> verify usage tracked
- Revoke key -> verify 401 on next request
- Expired key -> verify 401

### Task 27: Final Verify & Cleanup
- Run `make verify` — everything passes
- Run `ruff format .` and `ruff check .`
- Review all new files for consistency
