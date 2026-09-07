UV ?= uv
# Everything runs through `uv run`, which syncs the locked environment first. Override
# to use a plain interpreter instead: `make PY=python3 demo`.
PY ?= $(UV) run python
DEMO_CONFIG = examples/offline-demo.config.json
LOCAL_LOG = data/ipi_july_2026_run_log.local.csv
RUNS ?= runs

.PHONY: help sync lock upgrade demo demo-dspy plan list authz scan validate validate-json test check no-deps new-log new-corpus arena-scrape arena-parse clean

help:
	@echo "Setup:"
	@echo "  sync          Install the locked environment (uv sync --locked)"
	@echo "  lock          Re-resolve uv.lock after changing dependencies"
	@echo "  upgrade       Re-resolve uv.lock, allowing newer versions"
	@echo ""
	@echo "Red-team framework:"
	@echo "  demo          Offline end-to-end run against the simulator (no credentials)"
	@echo "  plan          Show the demo plan without sending anything"
	@echo "  list          List every registered probe, target, detector, transform"
	@echo "  authz         Inspect the example authorization record and its denylist"
	@echo "  scan          Credential/PII scan over runs/ before sharing anything"
	@echo ""
	@echo "Research data:"
	@echo "  validate      Validate the data/ compilation in strict mode"
	@echo "  validate-json Same, with JSON output"
	@echo "  new-log       Create a git-ignored local working copy of the run log"
	@echo "  new-corpus    Create a git-ignored operator corpus template"
	@echo "  arena-scrape  Scrape your Arena submissions via gs-submissions into arena/gs-scrape.local/"
	@echo "  arena-parse   Rebuild the arena/ scoreboard from saved captures"
	@echo ""
	@echo "Quality:"
	@echo "  test          Run the pytest suite"
	@echo "  no-deps       Prove the core CLI runs with nothing installed"
	@echo "  check         validate + test + no-deps"
	@echo "  clean         Remove caches and generated artifacts"

# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #
# --locked fails rather than silently re-resolving, so a stale lockfile is caught
# here instead of producing a run nobody can reproduce.
sync:
	$(UV) sync --locked

lock:
	$(UV) lock

upgrade:
	$(UV) lock --upgrade

# --------------------------------------------------------------------------- #
# Red-team framework
# --------------------------------------------------------------------------- #
# The demo targets the offline simulator, so it needs no authorization record and no
# credentials. It exits non-zero by design: the simulated targets have real guardrail
# failures, and a run that finds them is a run that worked.
demo:
	-$(PY) -m redteam run --config $(DEMO_CONFIG) --out $(RUNS)

demo-dspy:
	-$(UV) run redteam run --config examples/dspy-demo.config.json

plan:
	$(PY) -m redteam plan --config $(DEMO_CONFIG)

list:
	$(PY) -m redteam list

authz:
	-$(PY) -m redteam authz --auth examples/authorization.example.json \
		--target mock:balanced

scan:
	-$(PY) -m redteam scan $(RUNS)

# --------------------------------------------------------------------------- #
# Research data
# --------------------------------------------------------------------------- #
validate:
	$(PY) -m redteam validate --strict

validate-json:
	$(PY) -m redteam validate --json

new-log:
	@if [ -f "$(LOCAL_LOG)" ]; then \
		echo "$(LOCAL_LOG) already exists; not overwriting."; \
	else \
		cp data/ipi_july_2026_run_log.csv "$(LOCAL_LOG)"; \
		echo "Created $(LOCAL_LOG) (git-ignored). Log private results there."; \
	fi

new-corpus:
	@if [ -f "corpus.local.jsonl" ]; then \
		echo "corpus.local.jsonl already exists; not overwriting."; \
	else \
		cp examples/corpus.example.jsonl corpus.local.jsonl; \
		echo "Created corpus.local.jsonl (git-ignored). Put your approved"; \
		echo "harm-category prompts there, then pass --corpus corpus.local.jsonl"; \
	fi

# --------------------------------------------------------------------------- #
# Arena captures
# --------------------------------------------------------------------------- #
# The one remaining manual step is saving the challenge capture into
# arena/captures/challenge.local.json. Scraping and parsing then populate the
# git-ignored engagement artifacts.
arena-scrape:
	$(UV) run redteam arena-scrape

arena-parse:
	$(PY) scripts/arena_capture.py parse-challenge arena/captures/challenge.local.json --out arena
	$(PY) scripts/arena_capture.py convert-submissions arena/gs-scrape.local/*_submissions.jsonl --challenge arena/hazard_hunt_q3_challenge.local.json --out arena

# --------------------------------------------------------------------------- #
# Quality
# --------------------------------------------------------------------------- #
test:
	$(UV) run pytest

# --no-project installs nothing at all, so this fails the moment a third-party import
# creeps into the core CLI. The single pinned runtime dependency (grayswan-scraper)
# backs the arena-scrape surface only; every other command still runs on a bare
# interpreter, and that property is checked here rather than asserted.
no-deps:
	$(UV) run --no-project --isolated python -m redteam list >/dev/null
	$(UV) run --no-project --isolated python -m redteam validate --strict
	@echo "OK: the core CLI runs with no packages installed (the pinned grayswan-scraper dep is arena-scrape-only)"

check: validate test no-deps

clean:
	rm -rf .pytest_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
