"""Meta-tests for the data validator: the Report model, the generic validators, and
the guarantee that the shipped data compilation passes cleanly.

"Framework" in this repository now means the red-team framework, whose meta-tests
live in ``tests/framework/``. These are about ``redteam.datacheck``.
"""

from __future__ import annotations

import pytest

from redteam.datacheck.checks import ALL_CHECKS
from redteam.core.findings import Report, Severity
from redteam.datacheck.loaders import Table
from redteam.datacheck.schema import ColumnSpec, CsvSchema
from redteam.datacheck.validators import (
    validate_columns,
    validate_no_ragged_rows,
    validate_schema,
    validate_sequential_int,
    validate_unique,
)


def _table(name: str, header: list[str], rows: list[list[str]]) -> Table:
    dict_rows = [dict(zip(header, r + [""] * (len(header) - len(r)))) for r in rows]
    return Table(name=name, path=None, header=header, rows=dict_rows, raw_rows=rows)


# --- shipped data is clean ------------------------------------------------- #
def test_shipped_data_passes(full_report):
    assert full_report.ok(strict=False), full_report.to_text()


def test_shipped_data_passes_strict(full_report):
    # No warnings or infos are expected on the pristine compilation either.
    assert full_report.ok(strict=True), full_report.to_text(strict=True)


def test_no_findings_at_all_on_shipped_data(full_report):
    assert full_report.findings == [], full_report.to_text()


# --- Report semantics ------------------------------------------------------ #
def test_report_ok_rules():
    r = Report()
    assert r.ok(strict=True)
    r.info("c", "note")
    assert r.ok(strict=True)
    r.warning("c", "warn")
    assert r.ok(strict=False)
    assert not r.ok(strict=True)
    r.error("c", "boom")
    assert not r.ok(strict=False)


def test_report_json_roundtrip():
    r = Report()
    r.error("x", "msg", "f:1")
    d = r.to_dict()
    assert d["counts"]["error"] == 1
    assert d["findings"][0]["severity"] == "error"
    assert not d["ok"]


# --- generic validators fire on bad synthetic input ------------------------ #
def test_ragged_rows_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("a"), ColumnSpec("b")))
    table = _table("t.csv", ["a", "b"], [["1", "2"], ["3"]])
    r = Report()
    validate_no_ragged_rows(table, schema, r)
    assert any(f.check == "t.csv.ragged_rows" for f in r.errors)


def test_required_empty_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("a", required=True),))
    table = _table("t.csv", ["a"], [[""]])
    r = Report()
    validate_columns(table, schema, r)
    assert any("required but empty" in f.message for f in r.errors)


def test_enum_violation_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("a", enum=frozenset({"x", "y"})),))
    table = _table("t.csv", ["a"], [["z"]])
    r = Report()
    validate_columns(table, schema, r)
    assert any("not in" in f.message for f in r.errors)


def test_pattern_violation_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("a", pattern=r"\d+"),))
    table = _table("t.csv", ["a"], [["abc"]])
    r = Report()
    validate_columns(table, schema, r)
    assert any("does not match" in f.message for f in r.errors)


def test_whitespace_warns():
    schema = CsvSchema("t.csv", (ColumnSpec("a", required=False),))
    table = _table("t.csv", ["a"], [[" x "]])
    r = Report()
    validate_columns(table, schema, r)
    assert any(f.severity is Severity.WARNING for f in r.warnings)


def test_unique_column_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("a", unique=True),))
    table = _table("t.csv", ["a"], [["dup"], ["dup"]])
    r = Report()
    validate_unique(table, schema, r)
    assert any("duplicate" in f.message for f in r.errors)


def test_unique_composite_detected():
    schema = CsvSchema(
        "t.csv", (ColumnSpec("a"), ColumnSpec("b")), row_key=("a", "b")
    )
    table = _table("t.csv", ["a", "b"], [["1", "x"], ["1", "x"]])
    r = Report()
    validate_unique(table, schema, r)
    assert any(f.check.endswith("unique.a+b") for f in r.errors)


def test_sequential_int_detected():
    schema = CsvSchema("t.csv", (ColumnSpec("n"),))
    table = _table("t.csv", ["n"], [["1"], ["3"]])
    r = Report()
    validate_sequential_int(table, schema, "n", r)
    assert any("expected 2" in f.message for f in r.errors)


def test_header_mismatch_short_circuits_cell_checks():
    schema = CsvSchema("t.csv", (ColumnSpec("a"), ColumnSpec("b")))
    table = _table("t.csv", ["a", "WRONG"], [["1", "2"]])
    r = Report()
    validate_schema(table, schema, r)
    assert any(f.check == "t.csv.header" for f in r.errors)


# --- registry integrity ---------------------------------------------------- #
def test_all_checks_have_unique_names():
    names = [c.__name__ for c in ALL_CHECKS]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_each_check_is_callable_and_clean(check, dataset):
    r = Report()
    check(dataset, r)
    assert r.ok(strict=True), f"{check.__name__} produced: {r.to_text()}"
