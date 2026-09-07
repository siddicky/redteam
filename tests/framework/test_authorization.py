"""The authorization gate.

The most important tests in the repository. Everything else decides how well the
framework measures a target; these decide whether it is allowed to touch one at
all. Each test states the property it is protecting, because a future change that
breaks one of these turns a security tool into an unauthorized scanner.
"""

from __future__ import annotations

from datetime import date

import pytest

from redteam.core.errors import AuthorizationError, ConfigError, PolicyViolation
from redteam.policy.authorization import (
    BUILTIN_DENYLIST,
    Authorization,
    Scope,
    is_offline_endpoint,
)


# --------------------------------------------------------------------------- #
# Default deny
# --------------------------------------------------------------------------- #
def test_in_scope_endpoint_is_authorized(authorization):
    authorization.authorize("http://localhost:8080/v1/chat/completions")


def test_out_of_scope_endpoint_is_refused(authorization):
    """Default deny. An endpoint absent from scope.targets is never reachable."""
    with pytest.raises(AuthorizationError, match="not in the authorized scope"):
        authorization.authorize("https://api.example.com/v1/chat/completions")


def test_scope_rejects_catch_all_wildcards():
    """There is no 'authorize everything'. A blanket wildcard is not authorization."""
    for pattern in ("*", "**", "https://*", "*://*"):
        with pytest.raises(ConfigError, match="catch-all"):
            Scope.from_dict(
                {
                    "targets": [pattern],
                    "max_attempts": 10,
                    "max_requests_per_minute": 10,
                }
            )


def test_scope_requires_an_attempt_ceiling():
    with pytest.raises(ConfigError, match="max_attempts"):
        Scope.from_dict({"targets": ["mock:*"], "max_requests_per_minute": 10})


def test_scope_requires_a_rate_ceiling():
    with pytest.raises(ConfigError, match="max_requests_per_minute"):
        Scope.from_dict({"targets": ["mock:*"], "max_attempts": 10})


def test_scope_rejects_an_absurd_attempt_ceiling():
    with pytest.raises(ConfigError, match="exceeds the framework ceiling"):
        Scope.from_dict(
            {
                "targets": ["mock:*"],
                "max_attempts": 10_000_000,
                "max_requests_per_minute": 10,
            }
        )


def test_scope_requires_at_least_one_target():
    with pytest.raises(ConfigError, match="non-empty list"):
        Scope.from_dict({"targets": [], "max_attempts": 10, "max_requests_per_minute": 1})


# --------------------------------------------------------------------------- #
# The append-only denylist
# --------------------------------------------------------------------------- #
def test_builtin_denylist_starts_empty():
    assert BUILTIN_DENYLIST == ()


def test_denylisted_host_is_refused(authorization_record):
    authorization_record["scope"]["targets"].append("https://blocked.example.com/*")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    authorization = Authorization.from_dict(authorization_record)
    with pytest.raises(PolicyViolation, match="denied"):
        authorization.authorize("https://app.blocked.example.com/v1")


def test_denylist_covers_subdomains_and_paths(authorization_record):
    authorization_record["scope"]["targets"].append("blocked.example.com")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    authorization = Authorization.from_dict(authorization_record)
    for endpoint in (
        "https://blocked.example.com/",
        "https://app.blocked.example.com/api/submit",
        "https://deeply.nested.blocked.example.com/x/y/z?a=1",
    ):
        with pytest.raises(PolicyViolation):
            authorization.authorize(endpoint)


def test_denylist_wins_over_an_explicit_scope_entry(authorization_record):
    """Listing a denied host in scope must not unlock it."""
    authorization_record["scope"]["targets"].append("https://blocked.example.com/*")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    authorization = Authorization.from_dict(authorization_record)
    with pytest.raises(PolicyViolation):
        authorization.authorize("https://blocked.example.com/api/submit")


def test_denylist_is_append_only(authorization_record):
    """Operators can add denials; the built-ins always remain."""
    authorization_record["scope"]["deny"] = ["internal-prod.example.com"]
    authorization = Authorization.from_dict(authorization_record)
    patterns = [pattern for pattern, _ in authorization.denylist()]
    for builtin, _ in BUILTIN_DENYLIST:
        assert builtin in patterns
    assert "internal-prod.example.com" in patterns


def test_operator_added_denial_is_enforced(authorization_record):
    authorization_record["scope"]["targets"].append("http://prod.example.com/*")
    authorization_record["scope"]["deny"] = ["prod.example.com"]
    authorization = Authorization.from_dict(authorization_record)
    with pytest.raises(PolicyViolation):
        authorization.authorize("http://prod.example.com/v1/chat")


def test_denylist_matches_non_url_endpoints(authorization_record):
    """``exec:`` endpoints have no host, so they fall back to substring matching."""
    authorization_record["scope"]["deny"] = ["submit-bot"]
    authorization_record["scope"]["targets"].append("exec:*")
    authorization = Authorization.from_dict(authorization_record)
    with pytest.raises(PolicyViolation):
        authorization.authorize("exec:./bin/submit-bot")


def test_denylist_does_not_overmatch_a_similar_host(authorization_record):
    """``blocked.example.com`` must not deny ``myblocked.example.com.internal``."""
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    authorization_record["scope"]["targets"].append("https://myblocked.example.com.internal/*")
    authorization = Authorization.from_dict(authorization_record)
    authorization.authorize("https://myblocked.example.com.internal/v1/chat")


# --------------------------------------------------------------------------- #
# Expiry
# --------------------------------------------------------------------------- #
def test_expired_record_authorizes_nothing(expired_authorization):
    with pytest.raises(AuthorizationError, match="expired"):
        expired_authorization.authorize("mock:balanced")


def test_expiry_is_evaluated_against_a_supplied_date(authorization_record):
    authorization_record["expires"] = "2026-08-01"
    authorization = Authorization.from_dict(authorization_record)
    authorization.authorize("mock:balanced", today=date(2026, 7, 31))
    with pytest.raises(AuthorizationError, match="expired"):
        authorization.authorize("mock:balanced", today=date(2026, 8, 2))


def test_expiry_must_be_an_iso_date(authorization_record):
    authorization_record["expires"] = "next Tuesday"
    with pytest.raises(ConfigError, match="ISO date"):
        Authorization.from_dict(authorization_record)


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "acknowledgements",
    [
        {},
        {"authorized": True},
        {"rules_of_engagement_reviewed": True},
        {"authorized": False, "rules_of_engagement_reviewed": True},
        {"authorized": "yes", "rules_of_engagement_reviewed": "yes"},
    ],
)
def test_both_acknowledgements_are_required(authorization_record, acknowledgements):
    """A scaffolded file must not run until a human has affirmed both statements."""
    authorization_record["acknowledgements"] = acknowledgements
    with pytest.raises(ConfigError, match="acknowledgements"):
        Authorization.from_dict(authorization_record)


@pytest.mark.parametrize("field", ["engagement", "authorized_by", "expires"])
def test_required_fields_are_required(authorization_record, field):
    authorization_record[field] = ""
    with pytest.raises(ConfigError, match=field):
        Authorization.from_dict(authorization_record)


def test_unsupported_version_is_refused(authorization_record):
    authorization_record["version"] = 2
    with pytest.raises(ConfigError, match="unsupported authorization version"):
        Authorization.from_dict(authorization_record)


# --------------------------------------------------------------------------- #
# Offline authorization
# --------------------------------------------------------------------------- #
def test_offline_record_permits_only_offline_endpoints():
    offline = Authorization.offline()
    offline.authorize("mock:balanced")
    offline.authorize("replay:/tmp/run.json")
    with pytest.raises(AuthorizationError, match="needs an authorization record"):
        offline.authorize("https://api.example.com/v1/chat")


@pytest.mark.parametrize(
    "endpoint,offline",
    [
        ("mock:balanced", True),
        ("replay:/tmp/x.json", True),
        ("static:fixture", True),
        ("http://localhost:1/x", False),
        ("https://api.example.com", False),
        ("exec:./bin/agent", False),
    ],
)
def test_offline_endpoint_classification(endpoint, offline):
    assert is_offline_endpoint(endpoint) is offline


# --------------------------------------------------------------------------- #
# Ceilings
# --------------------------------------------------------------------------- #
def test_ceilings_take_the_lower_of_requested_and_authorized(authorization):
    assert authorization.effective_attempts(50) == 50
    assert authorization.effective_attempts(5000) == 1000
    assert authorization.effective_attempts(0) == 1000

    assert authorization.effective_rate(30) == 30
    assert authorization.effective_rate(10_000) == 600
    assert authorization.effective_rate(0) == 600

    assert authorization.effective_concurrency(2) == 2
    assert authorization.effective_concurrency(64) == 4


def test_concurrency_is_unbounded_when_the_record_omits_it(authorization_record):
    authorization_record["scope"].pop("max_concurrency")
    authorization = Authorization.from_dict(authorization_record)
    assert authorization.effective_concurrency(32) == 32


# --------------------------------------------------------------------------- #
# Scope matching
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "pattern,endpoint,allowed",
    [
        ("https://llm.example.com/*", "https://llm.example.com/v1/chat", True),
        ("https://llm.example.com/*", "https://llm.example.com", False),
        ("llm.example.com", "https://llm.example.com/anything", True),
        ("llm.example.com", "https://other.example.com/anything", False),
        # A bare host also covers its subdomains, matching denylist semantics.
        ("example.com", "https://llm.example.com/v1", True),
        # A scheme in the pattern is matched literally: http scope must not
        # silently authorize https, or the reverse.
        ("http://localhost:8080/*", "https://localhost:8080/v1", False),
        ("exec:./bin/agent", "exec:./bin/agent", True),
        ("exec:./bin/agent", "exec:./bin/other", False),
        ("mock:*", "mock:balanced", True),
    ],
)
def test_scope_matching(authorization_record, pattern, endpoint, allowed):
    authorization_record["scope"]["targets"] = [pattern]
    authorization = Authorization.from_dict(authorization_record)
    assert authorization.in_scope(endpoint) is allowed


# --------------------------------------------------------------------------- #
# The run record
# --------------------------------------------------------------------------- #
def test_record_carries_provenance_but_not_contacts(authorization_record):
    authorization_record["contacts"] = {"escalation": "person@example.com"}
    record = Authorization.from_dict(authorization_record).record()
    assert record["engagement"] == "test engagement"
    assert record["authorized_by"] == "test suite"
    assert record["reference"] == "TEST-1"
    assert record["scope"]["max_attempts"] == 1000
    # Contact details are personal data and a run artifact travels widely.
    assert "contacts" not in record
    assert "person@example.com" not in str(record)


def test_missing_authorization_file_names_the_fix(tmp_path):
    with pytest.raises(ConfigError, match="redteam init"):
        Authorization.load(tmp_path / "nope.json")
