"""Generic, schema-driven validators.

These are the reusable building blocks: they take a :class:`Table` plus a
:class:`CsvSchema` (or a single column) and append findings to a
:class:`Report`. File-specific business rules live in ``checks.py`` and call
into these.
"""

from __future__ import annotations

import re

from ..core.findings import Report
from .loaders import Table
from .schema import ColumnSpec, CsvSchema

_COMPILED: dict[str, re.Pattern[str]] = {}


def _full_match(pattern: str, value: str) -> bool:
    rx = _COMPILED.get(pattern)
    if rx is None:
        rx = re.compile(f"(?:{pattern})\\Z")
        _COMPILED[pattern] = rx
    return rx.match(value) is not None


def validate_header(table: Table, schema: CsvSchema, report: Report) -> bool:
    """Exact header match (names and order). Returns False when the header is
    wrong, since per-cell checks would otherwise misattribute values."""
    check = f"{schema.filename}.header"
    expected = schema.column_names
    if table.header != expected:
        report.error(
            check,
            f"header mismatch; expected {expected} got {table.header}",
            location=f"{schema.filename}:1",
        )
        return False
    return True


def validate_row_count(table: Table, schema: CsvSchema, report: Report) -> None:
    if schema.expected_row_count is None:
        return
    check = f"{schema.filename}.row_count"
    if table.row_count != schema.expected_row_count:
        report.error(
            check,
            f"expected {schema.expected_row_count} data rows, found {table.row_count}",
            location=schema.filename,
        )


def validate_no_ragged_rows(table: Table, schema: CsvSchema, report: Report) -> None:
    """Every data row must have exactly as many fields as the header."""
    check = f"{schema.filename}.ragged_rows"
    width = len(table.header)
    for line_no, fields in enumerate(table.raw_rows, start=2):
        if len(fields) != width:
            report.error(
                check,
                f"row has {len(fields)} fields, expected {width}",
                location=f"{schema.filename}:{line_no}",
            )


def validate_columns(table: Table, schema: CsvSchema, report: Report) -> None:
    """Per-cell required/enum/pattern/whitespace validation."""
    for spec in schema.columns:
        _validate_column(table, schema, spec, report)


def _validate_column(
    table: Table, schema: CsvSchema, spec: ColumnSpec, report: Report
) -> None:
    check = f"{schema.filename}.column.{spec.name}"
    for line_no, row in table.enumerate_rows():
        raw = row.get(spec.name, "")
        value = raw.strip()
        loc = f"{schema.filename}:{line_no}"

        if raw != value:
            report.warning(
                check,
                f"'{spec.name}' has leading/trailing whitespace: {raw!r}",
                location=loc,
            )

        if value == "":
            if spec.required:
                report.error(
                    check, f"'{spec.name}' is required but empty", location=loc
                )
            continue

        if spec.enum is not None and value not in spec.enum:
            report.error(
                check,
                f"'{spec.name}'={value!r} not in {sorted(spec.enum)}",
                location=loc,
            )
        if spec.pattern is not None and not _full_match(spec.pattern, value):
            report.error(
                check,
                f"'{spec.name}'={value!r} does not match /{spec.pattern}/",
                location=loc,
            )


def validate_unique(table: Table, schema: CsvSchema, report: Report) -> None:
    """Per-column uniqueness plus the schema's composite ``row_key``."""
    for spec in schema.columns:
        if not spec.unique:
            continue
        _validate_unique_column(table, schema, spec.name, report)

    if schema.row_key:
        _validate_unique_composite(table, schema, report)


def _validate_unique_column(
    table: Table, schema: CsvSchema, column: str, report: Report
) -> None:
    check = f"{schema.filename}.unique.{column}"
    seen: dict[str, int] = {}
    for line_no, row in table.enumerate_rows():
        value = row.get(column, "").strip()
        if value == "":
            continue
        if value in seen:
            report.error(
                check,
                f"duplicate '{column}'={value!r} (first seen at row {seen[value]})",
                location=f"{schema.filename}:{line_no}",
            )
        else:
            seen[value] = line_no


def _validate_unique_composite(
    table: Table, schema: CsvSchema, report: Report
) -> None:
    key = schema.row_key or ()
    check = f"{schema.filename}.unique.{'+'.join(key)}"
    seen: dict[tuple[str, ...], int] = {}
    for line_no, row in table.enumerate_rows():
        composite = tuple(row.get(k, "").strip() for k in key)
        if composite in seen:
            report.error(
                check,
                f"duplicate {key}={composite} (first seen at row {seen[composite]})",
                location=f"{schema.filename}:{line_no}",
            )
        else:
            seen[composite] = line_no


def validate_sequential_int(
    table: Table,
    schema: CsvSchema,
    column: str,
    report: Report,
    start: int = 1,
) -> None:
    """Column must be exactly ``start, start+1, ...`` in file order."""
    check = f"{schema.filename}.sequential.{column}"
    for offset, (line_no, row) in enumerate(table.enumerate_rows()):
        expected = start + offset
        value = row.get(column, "").strip()
        if value != str(expected):
            report.error(
                check,
                f"'{column}' expected {expected}, found {value!r}",
                location=f"{schema.filename}:{line_no}",
            )


def validate_schema(table: Table, schema: CsvSchema, report: Report) -> None:
    """Run the full generic battery for a table. Cell/unique checks are skipped
    when the header is wrong (they would be meaningless)."""
    header_ok = validate_header(table, schema, report)
    validate_row_count(table, schema, report)
    validate_no_ragged_rows(table, schema, report)
    if header_ok:
        validate_columns(table, schema, report)
        validate_unique(table, schema, report)
