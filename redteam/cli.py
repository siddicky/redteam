"""Command-line interface.

    redteam plan     --config C [--auth A]     show what would be sent, send nothing
    redteam run      --config C [--auth A]     execute a run and write artifacts
    redteam compile  --config C [--auth A]     optimize and save a DSPy program
    redteam list     probes|targets|...        enumerate the plugin registries
    redteam report   RUN.json --format md      re-render a saved run
    redteam compare  BASE.json HEAD.json       diff two runs (regression gate)
    redteam scan     PATH...                   credential/PII scan over artifacts
    redteam authz    --auth A [--target E]     inspect and test an authorization record
    redteam validate                           validate the research data in data/
    redteam init     [DIR]                     scaffold a config and authorization file

Exit codes are the contract with CI:

``0``
    Success. For ``run``: no finding at or above ``--fail-on``.
``1``
    Findings at or above the threshold (``run``, ``compare``), validation
    failure (``validate``, ``scan``), or compile failure after traffic started.
``2``
    The operator asked for something invalid or unauthorized. Nothing was sent.

The distinction between 1 and 2 is deliberate: a pipeline should treat "the target
has a vulnerability" and "your authorization file expired" as different events.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .core.errors import AuthorizationError, ConfigError, PolicyViolation, RedTeamError
from .core.redact import Redactor
from .core.result import AttemptResult, Outcome, Risk, RunResult
from .core.util import now_iso
from .detectors import DETECTORS
from .orchestrators import ORCHESTRATORS, execute_run, prepare_run
from .policy.authorization import Authorization, is_offline_endpoint
from .probes import PROBES
from .reporting import REPORTERS, ReportOptions, build_reporter, write_reports
from .targets import TARGETS
from .transforms import TRANSFORMS

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

REGISTRIES = {
    "probes": PROBES,
    "targets": TARGETS,
    "detectors": DETECTORS,
    "transforms": TRANSFORMS,
    "orchestrators": ORCHESTRATORS,
    "reporters": REPORTERS,
}


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description=(
            "Automated red-teaming framework for LLM and agent deployments. "
            "Every target must be covered by an authorization record; see "
            "docs/AUTHORIZATION.md."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    sub = parser.add_subparsers(dest="command")

    def add_run_like(name: str, help_text: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--config", "-c", required=True, metavar="FILE", help="run config (JSON or TOML)")
        sp.add_argument(
            "--auth",
            "-a",
            metavar="FILE",
            help=(
                "authorization record. Required unless every target is offline "
                "(mock:, replay:, static:)."
            ),
        )
        sp.add_argument("--target", action="append", metavar="ID", help="restrict to these target ids")
        sp.add_argument("--probe", action="append", metavar="SEL", help="probe selector (id, family, or glob)")
        sp.add_argument("--tag", action="append", metavar="TAG", help="only probes carrying this tag")
        sp.add_argument("--exclude-tag", action="append", metavar="TAG", help="skip probes carrying this tag")
        sp.add_argument("--transform", action="append", metavar="ID", help="transform to sweep (identity is always included)")
        sp.add_argument("--orchestrator", metavar="ID", help="sweep, crescendo, or adaptive")
        sp.add_argument("--seed", metavar="STR", help="run seed; the same seed reproduces the run")
        sp.add_argument("--max-attempts", type=int, metavar="N", help="attempt ceiling (still capped by the authorization record)")
        sp.add_argument("--max-payloads-per-probe", type=int, default=0, metavar="N", help="sample N payloads per probe (0 = all)")
        sp.add_argument("--rate", type=float, metavar="RPM", help="requests per minute")
        sp.add_argument("--concurrency", type=int, metavar="N", help="parallel requests")
        sp.add_argument("--corpus", metavar="FILE", help="JSONL corpus for the corpus.custom probe")
        sp.add_argument("--min-risk", metavar="LEVEL", help="only probes rated at this level or worse")
        return sp

    plan = add_run_like("plan", "show the attempt plan without sending anything")
    plan.add_argument("--json", action="store_true", help="emit the plan as JSON")
    plan.add_argument("--show-payloads", action="store_true", help="include payload text in the plan")

    run = add_run_like("run", "execute a run and write artifacts")
    run.add_argument("--out", metavar="DIR", help="artifact directory (default: config output_dir)")
    run.add_argument("--format", action="append", metavar="FMT", help="report format; repeatable")
    run.add_argument("--fail-on", metavar="LEVEL", help="exit 1 when a finding is at this risk or worse (default: any)")
    run.add_argument("--no-redact", action="store_true", help="do not redact credentials/PII from artifacts (not recommended)")
    run.add_argument("--no-payload-text", action="store_true", help="store payload fingerprints instead of payload text")
    run.add_argument("--quiet", "-q", action="store_true", help="suppress the console report")
    run.add_argument("--dry-run", action="store_true", help="alias for 'plan'")

    compile = add_run_like(
        "compile",
        "optimize the DSPy red-teamer program against a target and save it",
    )
    compile.add_argument(
        "--optimizer",
        choices=["mipro_v2"],
        default="mipro_v2",
        help="optimizer (default: mipro_v2)",
    )
    compile.add_argument(
        "--layers",
        type=int,
        metavar="N",
        help="Attack/Refine layers (default: config value or 3)",
    )
    compile.add_argument(
        "--demos",
        type=int,
        metavar="N",
        help="maximum bootstrapped demos (default: config value or 2)",
    )
    compile.add_argument(
        "--program-out",
        metavar="PATH",
        help="program artifact (default: <output_dir>/dspy-program.json)",
    )

    listing = sub.add_parser("list", help="enumerate the plugin registries")
    listing.add_argument("what", nargs="?", default="all", choices=[*REGISTRIES, "all"])
    listing.add_argument("--json", action="store_true", help="emit as JSON")
    listing.add_argument("--verbose", "-v", action="store_true", help="include metadata")

    report = sub.add_parser("report", help="re-render a saved run artifact")
    report.add_argument("run", metavar="RUN.json")
    report.add_argument("--format", "-f", default="markdown", help="output format (default markdown)")
    report.add_argument("--out", metavar="FILE", help="write here instead of stdout")
    report.add_argument("--no-payload-text", action="store_true", help="omit payload text")
    report.add_argument("--no-redact", action="store_true", help="do not redact")
    report.add_argument("--title", help="report title")

    compare = sub.add_parser("compare", help="diff two runs and gate on regressions")
    compare.add_argument("baseline", metavar="BASE.json")
    compare.add_argument("current", metavar="HEAD.json")
    compare.add_argument("--json", action="store_true", help="emit as JSON")

    scan = sub.add_parser(
        "scan", help="scan files for credentials and PII before sharing them"
    )
    scan.add_argument("paths", nargs="+", metavar="PATH")
    scan.add_argument("--json", action="store_true", help="emit as JSON")
    scan.add_argument("--fix", metavar="DIR", help="write redacted copies into DIR")

    authz = sub.add_parser("authz", help="inspect an authorization record")
    authz.add_argument("--auth", "-a", metavar="FILE", help="authorization record")
    authz.add_argument("--target", action="append", metavar="ENDPOINT", help="test whether an endpoint is authorized")
    authz.add_argument("--json", action="store_true", help="emit as JSON")

    validate = sub.add_parser("validate", help="validate the research data in data/")
    validate.add_argument("--data", metavar="DIR", help="data directory (default: ./data)")
    validate.add_argument("--json", action="store_true", help="emit findings as JSON")
    validate.add_argument("--strict", action="store_true", help="treat warnings as failures")
    validate.add_argument("--quiet", action="store_true", help="suppress INFO findings")
    validate.add_argument("--list", action="store_true", help="list the registered checks")

    init = sub.add_parser("init", help="scaffold a config and authorization template")
    init.add_argument("directory", nargs="?", default=".", metavar="DIR")
    init.add_argument("--force", action="store_true", help="overwrite existing files")

    return parser


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _load_config(args: argparse.Namespace):
    from .core.config import RunConfig

    config = RunConfig.load(args.config)

    if getattr(args, "target", None):
        wanted = set(args.target)
        unknown = wanted - {t.id for t in config.targets}
        if unknown:
            raise ConfigError(
                f"--target named {', '.join(sorted(unknown))}, which the config does "
                f"not define. Available: {', '.join(t.id for t in config.targets)}"
            )
        config.targets = [t for t in config.targets if t.id in wanted]
    if getattr(args, "probe", None):
        config.probes = list(args.probe)
    if getattr(args, "tag", None):
        config.include_tags = list(args.tag)
    if getattr(args, "exclude_tag", None):
        config.exclude_tags = list(args.exclude_tag)
    if getattr(args, "transform", None):
        config.transforms = list(args.transform)
        if "identity" not in config.transforms:
            config.transforms.insert(0, "identity")
    if getattr(args, "orchestrator", None):
        config.orchestrator = args.orchestrator
    if getattr(args, "seed", None):
        config.seed = args.seed
    if getattr(args, "max_attempts", None):
        config.max_attempts = args.max_attempts
    if getattr(args, "rate", None):
        config.requests_per_minute = args.rate
    if getattr(args, "concurrency", None):
        config.concurrency = args.concurrency
    if getattr(args, "min_risk", None):
        config.min_risk = Risk.parse(args.min_risk)
    if getattr(args, "out", None):
        config.output_dir = args.out
    if getattr(args, "format", None):
        config.formats = list(args.format)
    if getattr(args, "no_redact", False):
        config.redact_artifacts = False
    if getattr(args, "no_payload_text", False):
        config.include_payload_text = False
    return config


def _load_authorization(args: argparse.Namespace, config) -> Authorization:
    """Load the record, or fall back to the offline-only implicit authorization.

    The fallback is available *only* when every configured target is offline. That
    keeps the demo and test paths frictionless without teaching operators that the
    gate is optional — point the same config at a URL and it fails immediately.
    """
    if getattr(args, "auth", None):
        return Authorization.load(args.auth)

    from .targets import build_target

    endpoints: list[str] = []
    for target_config in config.targets:
        endpoints.append(build_target(target_config, timeout=config.timeout).endpoint)
    live = [e for e in endpoints if not is_offline_endpoint(e)]
    if live:
        raise AuthorizationError(
            "no authorization record supplied, but this config targets live "
            f"endpoint(s): {', '.join(live)}.\n"
            "Pass --auth authorization.json. Run 'redteam init' to scaffold one, and "
            "have the engagement signed off before you run it.\n"
            "Only offline targets (mock:, replay:, static:) run without a record."
        )
    return Authorization.offline()


def _report_options(config, *, title: str = "AI red-team assessment") -> ReportOptions:
    return ReportOptions(
        include_payload_text=config.include_payload_text,
        include_raw_responses=config.include_raw_responses,
        redact=config.redact_artifacts,
        title=title,
    )


def _print_plan_text(plan, config) -> None:
    print(f"plan       : {plan.orchestrator}   seed={plan.seed}")
    print(f"targets    : {len(plan.targets)}")
    for target_id, endpoint in plan.targets.items():
        print(f"             {target_id} -> {endpoint}")
    print(f"probes     : {len(plan.probes)}  ({', '.join(plan.probes)})")
    print(f"transforms : {', '.join(plan.transforms)}")
    print(
        f"attempts   : {len(plan.sendable)} to send, {len(plan.skipped)} skipped, "
        f"~{plan.request_estimate()} request(s)"
    )
    print(f"rate limit : {config.requests_per_minute:g} req/min, concurrency {config.concurrency}")
    if plan.truncated:
        print("TRUNCATED  : the plan exceeded the authorized attempt ceiling")
    print()

    by_probe: dict[str, int] = {}
    for attempt in plan.sendable:
        by_probe[attempt.payload.probe] = by_probe.get(attempt.payload.probe, 0) + 1
    if by_probe:
        print("attempts by probe:")
        for probe, count in sorted(by_probe.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {probe:<36} {count}")
        print()

    if plan.skipped:
        print("skipped (these establish nothing — not passes):")
        reasons: dict[str, int] = {}
        for attempt in plan.skipped:
            reasons[attempt.skip_reason] = reasons.get(attempt.skip_reason, 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"  {count}x {reason}")
        print()

    for note in plan.notes:
        print(f"note: {note}")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_plan(args: argparse.Namespace) -> int:
    config = _load_config(args)
    authorization = _load_authorization(args, config)
    _, plan, ctx = prepare_run(
        config,
        authorization,
        seed=config.seed,
        max_payloads_per_probe=args.max_payloads_per_probe,
        corpus_path=getattr(args, "corpus", "") or "",
    )
    plan.notes.extend(n for n in ctx.notes if n not in plan.notes)
    if getattr(args, "json", False):
        print(json.dumps(plan.to_dict(include_text=args.show_payloads), indent=2, default=str))
    else:
        _print_plan_text(plan, config)
        if args.show_payloads:
            print("payloads:")
            for attempt in plan.sendable:
                print(f"\n--- {attempt.target_id} :: {attempt.payload.probe}/{attempt.payload.payload_id}")
                print(attempt.payload.attack_text()[:2000])
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    if getattr(args, "dry_run", False):
        args.json = False
        args.show_payloads = False
        return cmd_plan(args)

    config = _load_config(args)
    authorization = _load_authorization(args, config)
    fail_on = Risk.parse(args.fail_on) if args.fail_on else config.fail_on

    progress_state = {"done": 0}

    def on_attempt(attempt: AttemptResult) -> None:
        progress_state["done"] += 1
        if args.quiet:
            return
        marker = {
            Outcome.BYPASSED: "!",
            Outcome.BLOCKED: ".",
            Outcome.INCONCLUSIVE: "?",
            Outcome.ERROR: "E",
            Outcome.SKIPPED: "-",
        }.get(attempt.outcome, ".")
        sys.stderr.write(marker)
        sys.stderr.flush()

    orchestrator, plan, ctx = prepare_run(
        config,
        authorization,
        seed=config.seed,
        max_payloads_per_probe=args.max_payloads_per_probe,
        corpus_path=getattr(args, "corpus", "") or "",
        on_attempt=on_attempt,
    )

    if not args.quiet:
        print(
            f"running {len(plan.sendable)} attempt(s) against "
            f"{len(plan.targets)} target(s) "
            f"(~{plan.request_estimate()} request(s), "
            f"{config.requests_per_minute:g} req/min)",
            file=sys.stderr,
        )
    result = execute_run(orchestrator, plan, ctx)
    if not args.quiet:
        sys.stderr.write("\n\n")
        sys.stderr.flush()

    options = _report_options(config)
    if not args.quiet:
        print(build_reporter("console").render(result, options))

    written = write_reports(result, config.formats, config.output_dir, options)
    if written and not args.quiet:
        print()
        for path in written:
            print(f"wrote {path}")

    passed = result.ok(fail_on=fail_on)
    if not passed and not args.quiet:
        threshold = fail_on.value if fail_on else "any"
        print(
            f"\nFAIL: findings at or above '{threshold}' risk.",
            file=sys.stderr,
        )
    return EXIT_OK if passed else EXIT_FINDINGS


def cmd_compile(args: argparse.Namespace) -> int:
    config = _load_config(args)
    authorization = _load_authorization(args, config)
    options = dict(config.orchestrator_options)
    layers = args.layers if args.layers is not None else int(options.get("layers", 3))
    demos = args.demos if args.demos is not None else int(options.get("demos", 2))
    options.update(
        {
            "optimizer": args.optimizer,
            "layers": layers,
            "demos": demos,
        }
    )
    config.orchestrator = "dspy.redteamer"
    config.orchestrator_options = options
    if len(config.targets) != 1:
        raise ConfigError(
            "redteam compile requires exactly one system-under-test target after "
            f"filtering; found {len(config.targets)}"
        )

    try:
        orchestrator, plan, ctx = prepare_run(
            config,
            authorization,
            seed=config.seed,
            max_payloads_per_probe=args.max_payloads_per_probe,
            corpus_path=getattr(args, "corpus", "") or "",
        )
    except RedTeamError as exc:
        print(f"\ncompile rejected before sending: {exc}", file=sys.stderr)
        return EXIT_USAGE

    from .dspy.compile import CompileOptions
    from .dspy.compile import run as compile_program

    program_out = Path(args.program_out) if args.program_out else Path(
        config.output_dir
    ) / "dspy-program.json"
    try:
        result = compile_program(
            orchestrator,
            plan,
            ctx,
            CompileOptions(
                program_out=program_out,
                optimizer=args.optimizer,
                layers=layers,
                demos=demos,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary maps failures by send count
        sent = ctx.budget.spent
        stage = "after traffic started" if sent else "before sending"
        print(f"\ncompile failed {stage}: {exc}", file=sys.stderr)
        return EXIT_FINDINGS if sent else EXIT_USAGE

    print(f"wrote {result.artifact}")
    print(f"requests issued: {result.requests_issued}")
    print(f"exclusions: {result.exclusions}")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    wanted = list(REGISTRIES) if args.what == "all" else [args.what]
    if args.json:
        payload = {
            kind: [
                {"id": e.id, "summary": e.summary, "tags": sorted(e.tags)}
                for e in REGISTRIES[kind]
            ]
            for kind in wanted
        }
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    for kind in wanted:
        registry = REGISTRIES[kind]
        print(f"{kind} ({len(registry)}):")
        for entry in registry:
            print(f"  {entry.id:<34} {entry.summary}")
            if args.verbose and entry.tags:
                print(f"  {'':<34} tags: {', '.join(sorted(entry.tags))}")
        print()
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.run)
    if not path.is_file():
        raise ConfigError(f"run artifact not found: {path}")
    try:
        result = RunResult.from_json(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid run JSON — {exc}") from None

    options = ReportOptions(
        include_payload_text=not args.no_payload_text,
        redact=not args.no_redact,
        title=args.title or "AI red-team assessment",
    )
    reporter = build_reporter(args.format)
    text = reporter.render(result, options)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    from .scoring.metrics import compare

    baseline = RunResult.from_json(Path(args.baseline).read_text(encoding="utf-8"))
    current = RunResult.from_json(Path(args.current).read_text(encoding="utf-8"))
    diff = compare(baseline.attempts, current.attempts)

    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        print(f"baseline {baseline.run_id}: ASR {diff['baseline_asr']['percent']}%")
        print(f"current  {current.run_id}: ASR {diff['current_asr']['percent']}%")
        print()
        print(f"fixed          : {len(diff['fixed'])}")
        for key in diff["fixed"][:20]:
            print(f"  + {key}")
        print(f"regressed      : {len(diff['regressed'])}")
        for key in diff["regressed"][:20]:
            print(f"  - {key}")
        print(f"still failing  : {len(diff['still_failing'])}")
        if diff["only_in_current"]:
            print(f"new attempts   : {len(diff['only_in_current'])} (not in baseline)")
        if diff["only_in_baseline"]:
            print(
                f"missing        : {len(diff['only_in_baseline'])} baseline attempt(s) "
                f"absent from the current run — coverage shrank"
            )
    return EXIT_FINDINGS if diff["regressed"] else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    """Credential and PII scan over arbitrary files.

    The pre-share gate: run it on a run artifact, a ticket attachment, or a
    directory of notes before any of it leaves the engagement.
    """
    redactor = Redactor()
    files: list[Path] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(
                p
                for p in sorted(path.rglob("*"))
                if p.is_file()
                and not any(part.startswith(".") or part == "__pycache__" for part in p.parts)
            )
        elif path.is_file():
            files.append(path)
        else:
            raise ConfigError(f"path not found: {path}")

    hits: list[dict] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:  # pragma: no cover - unreadable file
            hits.append({"file": str(file), "error": str(exc)})
            continue
        for match in redactor.scan(text):
            hits.append(
                {
                    "file": str(file),
                    "line": match.line,
                    "label": match.label,
                    "preview": f"[{match.label}]",
                }
            )
        if args.fix:
            destination = Path(args.fix) / file.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(redactor.apply(text), encoding="utf-8")

    if args.json:
        print(json.dumps({"scanned": len(files), "hits": hits}, indent=2))
    else:
        print(f"scanned {len(files)} file(s)")
        for hit in hits:
            if "error" in hit:
                print(f"  {hit['file']}: {hit['error']}")
            else:
                print(f"  {hit['file']}:{hit['line']}  {hit['label']}")
        if not hits:
            print("  no credentials or PII patterns found")
        else:
            print(
                f"\n{len(hits)} hit(s). Values are not printed. "
                + (f"Redacted copies written to {args.fix}." if args.fix else
                   "Re-run with --fix DIR to write redacted copies.")
            )
    return EXIT_FINDINGS if any("error" not in h for h in hits) else EXIT_OK


def cmd_authz(args: argparse.Namespace) -> int:
    authorization = (
        Authorization.load(args.auth) if args.auth else Authorization.offline()
    )
    checks: list[dict] = []
    for endpoint in args.target or []:
        try:
            authorization.authorize(endpoint)
            checks.append({"endpoint": endpoint, "allowed": True, "reason": ""})
        except (AuthorizationError, PolicyViolation) as exc:
            checks.append({"endpoint": endpoint, "allowed": False, "reason": str(exc)})

    if args.json:
        print(
            json.dumps(
                {
                    "record": authorization.record(),
                    "expired": authorization.is_expired(),
                    "days_remaining": authorization.days_remaining(),
                    "denylist": [
                        {"pattern": p, "reason": r} for p, r in authorization.denylist()
                    ],
                    "checks": checks,
                },
                indent=2,
            )
        )
    else:
        print(authorization.summary())
        if authorization.is_expired():
            print("\n  STATUS: EXPIRED — this record authorizes nothing")
        print("\nnon-overridable denylist:")
        for pattern, reason in authorization.denylist():
            print(f"  {pattern}")
            print(f"    {reason}")
        if checks:
            print("\nendpoint checks:")
            for check in checks:
                verdict = "ALLOW" if check["allowed"] else "DENY "
                print(f"  {verdict}  {check['endpoint']}")
                if check["reason"]:
                    print(f"         {check['reason']}")
    if authorization.is_expired():
        return EXIT_USAGE
    return EXIT_OK if all(c["allowed"] for c in checks) else EXIT_USAGE


def cmd_validate(args: argparse.Namespace) -> int:
    from .datacheck import ALL_CHECKS, load_dataset, run_all
    from .datacheck.loaders import DataLoadError

    if args.list:
        for check in ALL_CHECKS:
            doc = (check.__doc__ or "").strip().splitlines()
            print(f"{check.__name__}: {doc[0] if doc else ''}")
        return EXIT_OK

    try:
        dataset = load_dataset(args.data)
    except DataLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = run_all(dataset)
    if args.json:
        print(report.to_json(strict=args.strict))
    else:
        print(report.to_text(strict=args.strict, show_info=not args.quiet))
    return EXIT_OK if report.ok(strict=args.strict) else EXIT_FINDINGS


CONFIG_TEMPLATE = {
    "seed": "change-me-for-a-reproducible-run",
    "orchestrator": "sweep",
    "targets": [
        {
            "id": "offline-demo",
            "plugin": "mock.llm",
            "options": {"profile": "balanced"},
        },
        {
            "id": "staging-assistant",
            "plugin": "http.openai_compat",
            "options": {
                "url": "https://llm.staging.internal.example.com/v1/chat/completions",
                "model": "assistant-v3",
                # The ':-' fallback keeps the scaffolded file loadable before the
                # variable is exported, so 'redteam plan' works immediately after
                # 'redteam init'. Export the real key before running against a live
                # endpoint; an empty value sends no Authorization header, which the
                # endpoint will reject loudly rather than silently.
                "api_key": "${env:INTERNAL_LLM_KEY:-}",
            },
        },
    ],
    "probes": ["indirect", "direct", "leak.system_prompt", "agency"],
    "transforms": ["identity", "encoding.base64", "unicode.zero_width"],
    "max_attempts": 200,
    "requests_per_minute": 30,
    "concurrency": 2,
    "fail_on": "high",
    "output_dir": "runs",
    "formats": ["json", "markdown", "html"],
}

AUTHORIZATION_TEMPLATE = {
    "version": 1,
    "engagement": "DESCRIBE THE ENGAGEMENT",
    "authorized_by": "NAME AND ROLE OF THE PERSON WHO APPROVED IT",
    "reference": "TICKET-OR-CONTRACT-ID",
    "issued": "2026-07-30",
    "expires": "2026-08-30",
    "scope": {
        "targets": [
            "mock:*",
            "http://localhost:*",
            "https://llm.staging.internal.example.com/*",
        ],
        "max_attempts": 500,
        "max_requests_per_minute": 30,
        "max_concurrency": 4,
        "deny": [],
    },
    "acknowledgements": {
        "authorized": False,
        "rules_of_engagement_reviewed": False,
    },
    "contacts": {"escalation": "secops@example.com"},
    "notes": (
        "Set both acknowledgements to true only once the engagement is genuinely "
        "authorized and you have read the rules of engagement. Narrow scope.targets "
        "to the systems actually covered."
    ),
}


def cmd_init(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, template in (
        ("redteam.config.json", CONFIG_TEMPLATE),
        ("authorization.json", AUTHORIZATION_TEMPLATE),
    ):
        path = directory / name
        if path.exists() and not args.force:
            print(f"skip  {path} (exists; use --force to overwrite)")
            continue
        path.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
        written.append(path)
        print(f"wrote {path}")

    if written:
        print()
        print("Next steps:")
        print("  1. Edit authorization.json: describe the engagement, narrow the")
        print("     scope to the systems you may test, and set both acknowledgements")
        print("     to true once it is genuinely authorized.")
        print("  2. Edit redteam.config.json: point the targets at your systems, and")
        print("     export any ${env:...} credentials it references.")
        print("  3. redteam plan --config redteam.config.json --auth authorization.json")
        print("  4. redteam run  --config redteam.config.json --auth authorization.json")
        print("  5. For harm-category scoring, add a detector_options block for")
        print("     judge.llm (or judge.dspy — needs the dspy extra); see")
        print("     examples/README.md, and add the judge host to scope.targets.")
        print()
        print(f"Scaffolded {now_iso()}. authorization.json is git-ignored by default.")
    return EXIT_OK


COMMANDS = {
    "plan": cmd_plan,
    "run": cmd_run,
    "compile": cmd_compile,
    "list": cmd_list,
    "report": cmd_report,
    "compare": cmd_compare,
    "scan": cmd_scan,
    "authz": cmd_authz,
    "validate": cmd_validate,
    "init": cmd_init,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        from . import __version__

        print(f"redteam {__version__}")
        return EXIT_OK
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    handler = COMMANDS[args.command]
    try:
        return handler(args)
    except PolicyViolation as exc:
        print(f"\nREFUSED: {exc}", file=sys.stderr)
        print(
            "This denial is not configurable. The platform's own rules forbid "
            "automated interaction.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except AuthorizationError as exc:
        print(f"\nNOT AUTHORIZED: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConfigError as exc:
        print(f"\nconfig error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except RedTeamError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("\ninterrupted", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
