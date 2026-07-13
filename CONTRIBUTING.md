# Contributing to PCAP Hunter

Thanks for your interest in contributing. This is a concise guide to how the
repo actually works day-to-day — see `CLAUDE.md` for the full architecture
and conventions reference.

## Getting set up

```bash
git clone <repo-url>
cd pcap-hunter
make install          # delegates to scripts/install.py (cross-platform)
```

`make install` installs both system binaries (tshark, Zeek, etc.) and Python
dependencies, then verifies them. Useful variants:

```bash
make install-system   # system binaries only
make install-python   # Python packages only
make check-deps       # or `make doctor` — verify everything is present
```

Run the app locally with:

```bash
make run              # streamlit run app/main.py (checks deps first)
```

## Before you commit: `make verify`

**`make verify` is the pre-commit gate and it must pass before every
commit.** It runs, in order:

1. `ruff format --check .` — formatting check
2. `ruff check .` — lint
3. `PYTHONPATH=. pytest tests/ -q` — full test suite

```bash
make verify
```

CI (`.github/workflows/ci.yml`) runs the same three checks on every push and
PR to `main`, plus an advisory `pip-audit` dependency-scan job and a Docker
build/test job. If `make verify` passes locally, it will pass in CI.

You can also run the pieces individually:

```bash
make test             # PYTHONPATH=. pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=58
make test-pdf         # focused PDF/chart smoke tests — run after touching pdf_generator.py, chart_images.py, or the charts module
make lint             # ruff check .
make format           # ruff format .
```

Always run tests with `PYTHONPATH=.` (or via `make test`/`make verify`,
which set it for you) — the codebase uses absolute imports
(`from app.pipeline.beacon import rank_beaconing`) and needs it on the path.

### Host-Python caveat

macOS machines frequently have multiple coexisting Python installs (Framework
Python, Homebrew Python, pyenv, etc.). `make test`/`make verify` use whichever
interpreter `streamlit` is installed under (see the `PYTHON` detection at the
top of the `Makefile`), but if your environment has `pytest` and other
dependencies split across interpreters, `make verify` on the host can fail
in ways that don't reflect a real problem. If you hit interpreter confusion:

- confirm `pip show pytest` and `pip show streamlit` agree on the same
  interpreter, or
- fall back to the canonical, environment-independent path below.

### Docker: the canonical build-and-verify path

Any verification that depends on a clean install (dependency changes,
install-path changes, or anything you want to be **certain** works outside
your local environment) should go through Docker rather than the host:

```bash
make docker-verify    # builds the `test` image and runs format+lint+tests inside it
make docker-up         # build + run the UI at http://localhost:8501
make docker-down
```

This mirrors what CI's `docker` job does and is the same environment the app
ships in, so it's the most trustworthy signal for anything build-shaped.

## Code conventions

- **Style**: Ruff, line length 120, double quotes, 4-space indent (see the
  `select` list and per-file ignores in `pyproject.toml` for the exact rules)
- **Imports**: absolute only (`from app.pipeline.beacon import ...`),
  stdlib → third-party → local, ordering enforced by ruff's `I` rule
- **Naming**: `snake_case.py` modules, `PascalCase` classes, `snake_case`
  functions, `UPPER_SNAKE_CASE` constants, leading underscore for private
  helpers
- **Data modeling**: prefer `dataclass` for structured data, `Enum` for
  fixed categories
- **Errors/logging**: custom exceptions inherit from `Exception`; use the
  `logging` module, never `print()`
- **Type hints**: used extensively, with `from __future__ import annotations`
  for forward compatibility
- **Docstrings**: Google-style (`Args`/`Returns`) on public functions

## Tests

- One test file per major module: `tests/test_<module>.py`
- Test classes `Test<Feature>`, test functions `test_<scenario>`
- Cover both the happy path and edge cases (empty, `None`, malformed input)
- **Use production-shape test data.** If a function consumes
  `list[CorrelationSignal]` dataclasses, pass real dataclass instances in
  tests, not dicts with similar-looking keys — simplified test inputs have
  previously let real bugs ship. See `tests/test_pdf_integration.py` for the
  expected shapes.
- No shared `conftest.py` fixtures — tests are independent
- New PDF sections need a corresponding assertion in
  `tests/test_pdf_integration.py::test_html_contains_every_expected_section`;
  new PDF charts need a kaleido smoke test in `tests/test_chart_rendering.py`

## Commit messages

Conventional-commits style, lowercase description after the prefix:

```
feat: add single-ioc exact-match lookup endpoint
fix: escape crlf in cef output to prevent syslog log injection
docs: refresh readme and user manuals
chore: cover all runtime deps in dependency check
```

Common prefixes: `feat:`, `fix:`, `docs:`, `style:`, `chore:`.

## Submitting changes

1. Make your change, keeping it focused.
2. Run `make verify` (and `make docker-verify` if the change touches
   dependencies, install paths, or anything build-shaped).
3. Commit using the conventions above.
4. Open a pull request against `main` describing what changed and why.

CI must pass (tests + coverage floor, lint, format check) before a PR can be
merged.
