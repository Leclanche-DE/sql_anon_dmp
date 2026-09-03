#!/usr/bin/env python3
"""
mariadb_anon_dump.py
====================

Dump selected tables from a MariaDB server, with per-column transformations:

  * Anonymization  (bijective character substitution for strings)
  * Obfuscation    (linear transformation y = a * x for numbers)
  * Column removal (drop columns from the output entirely)
  * Row filtering  (WHERE clause per table)

The anonymization is a fixed character permutation over the printable
ASCII range (0x20..0x7E) plus the common whitespace chars. Because it is a
permutation it is bijective: applying the inverse permutation recovers the
original string exactly. The permutation is derived deterministically from
a seed, so two runs with the same seed produce the same mapping and the
inverse is always computable.

Output: a SQL file with INSERT statements (re-importable), one file per
table. Optionally also CSV per table.

Requirements:
    pip install pymysql cryptography   # cryptography only if you use
                                       # sha256_password / caching_sha2_password

Usage:
    python mariadb_anon_dump.py --config config.json
    python mariadb_anon_dump.py            # uses built-in CONFIG below

See CONFIG and ANON_CONFIG / OBFUSC_CONFIG at the top of this file to
customize. Everything is also overridable via a JSON config file.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

try:
    import pymysql
    from pymysql.constants import FIELD_TYPE
    from pymysql.err import OperationalError, ProgrammingError
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: PyMySQL is required. Install it with:\n"
        "    pip install pymysql cryptography\n"
    )
    raise


# ============================================================================
#  CONFIGURATION
# ============================================================================
#
#  Edit this block to match your environment and tables.
#  You can also pass a JSON file with the same structure via --config.

CONFIG: Dict[str, Any] = {
    # --- Connection -------------------------------------------------------
    "connection": {
        "host": "localhost",
        "port": 3306,
        "user": "readonly_user",
        "password": os.environ.get("MARIADB_PASSWORD", ""),
        "database": "your_database",
        "charset": "utf8mb4",
        # Connect with SSL if your server requires it:
        "ssl": None,          # or {"ssl": {"ca": "/path/to/ca.pem"}}
        "connect_timeout": 10,
    },

    # --- Output -----------------------------------------------------------
    "output": {
        "dir": "./dump_out",          # where SQL/CSV files are written
        "format": "sql",              # "sql", "csv", or "both"
        "sql_batch_size": 500,        # rows per INSERT statement
        "include_drop_table": False,  # prepend DROP TABLE IF EXISTS
        "include_create_table": False,# prepend a CREATE TABLE for the
                                      # *transformed* schema (no removed cols)
        "csv_quoting": csv.QUOTE_MINIMAL,
    },

    # --- Global transform settings ---------------------------------------
    "anonymization": {
        # Seed for the deterministic character permutation.
        # CHANGE THIS and keep it secret + backed up: it IS your key.
        # Anyone with the seed can reverse the anonymization.
        "seed": 1337,
    },

    "obfuscation": {
        # Default linear factor used when a column does not specify its own.
        # y = factor * x   (reverse: x = y / factor)
        "default_factor": 3.6,
        # Decimal places to keep when rounding the obfuscated value.
        "default_round": 4,
    },

    # --- Tables -----------------------------------------------------------
    # One entry per table. Add as many as you need.
    "tables": [
        {
            "schema": "database_name",       # database/schema name, or null
            "table": "table_name",

            # WHERE filter applied to the SELECT.
            "where": (
                "that_column IN ("
                "'A','B',"
                "'C')"
            ),

            # Columns to drop entirely from the output (never selected for
            # transformation, never written). GENERATED columns MUST be
            # listed here (or in skip) because they cannot be inserted into
            # the target table.
            "remove_columns": [],

            # Columns whose string value is anonymized via the bijective
            # character permutation.
            "anonymize_columns": [
            ],

            # Columns whose numeric value is obfuscated with a linear map.
            # Each entry can override the global factor / rounding.
            "obfuscate_columns": [
                # {"column": "quantity", "factor": 3.6, "round": 4},
                "quantity",   # uses defaults from obfuscation.* above
            ],

            # Optional ORDER BY for deterministic dump order.
            "order_by": "id",
        },
        # -----------------------------------------------------------------
        # Add more tables here following the same shape.
        # -----------------------------------------------------------------
    ],
}


# ============================================================================
#  ANONYMIZATION  (bijective character permutation)
# ============================================================================

# The alphabet we permute. Every char in a string that is NOT in this set is
# left untouched (so non-ASCII / unusual bytes pass through unchanged). That
# keeps the mapping total but means the cipher only protects the chosen
# alphabet. For European business strings this covers everything you need.
ANON_ALPHABET: str = (
    # digits
    "0123456789"
    # uppercase letters
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # lowercase letters
    "abcdefghijklmnopqrstuvwxyz"
    # common punctuation / symbols used in lot & article numbers
    " .-_/()*+#:!?&@=[]{}<>\"'$%;,|^~`"
)


@dataclass
class Anonymizer:
    """Bijective character substitution over ANON_ALPHABET.

    Forward  = permutation P
    Inverse  = inverse permutation P^{-1}
    Both are deterministic for a given seed.
    """
    seed: int

    def __post_init__(self) -> None:
        chars = list(ANON_ALPHABET)
        # Deterministic shuffle seeded with the key. random.Random is stable
        # across Python versions for a given seed.
        rng = random.Random(self.seed)
        shuffled = chars[:]
        rng.shuffle(shuffled)
        self._forward: Dict[str, str] = dict(zip(chars, shuffled))
        self._inverse: Dict[str, str] = dict(zip(shuffled, chars))

    def forward(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return "".join(self._forward.get(c, c) for c in value)

    def inverse(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return "".join(self._inverse.get(c, c) for c in value)


# ============================================================================
#  OBFUSCATION  (linear transformation, reversible)
# ============================================================================

@dataclass
class Obfuscator:
    """y = factor * x, rounded to `round` decimals.

    Reverse: x = y / factor, rounded to `round` decimals.
    We use Decimal to avoid binary floating-point drift on decimal(18,4).
    """
    factor: Decimal
    round: int

    @classmethod
    def from_cfg(cls, factor: float, rnd: int) -> "Obfuscator":
        return cls(factor=Decimal(str(factor)), round=rnd)

    def forward(self, value: Optional[Decimal]) -> Optional[str]:
        if value is None:
            return None
        result = (value * self.factor).quantize(
            Decimal(1).scaleb(-self.round), rounding=ROUND_HALF_UP
        )
        # Normalize removes trailing zeros for cleaner SQL: 3.6000 -> 3.6
        return str(result.normalize())

    def inverse(self, value: Optional[Decimal]) -> Optional[str]:
        if value is None:
            return None
        result = (value / self.factor).quantize(
            Decimal(1).scaleb(-self.round), rounding=ROUND_HALF_UP
        )
        return str(result.normalize())


# ============================================================================
#  SQL HELPERS
# ============================================================================

def sql_escape(value: Any) -> str:
    """Render a Python value as a SQL literal safe for INSERT."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, float):
        # Avoid scientific notation for plain numeric columns.
        return repr(value)
    # bytes (e.g. BINARY) -> hex blob literal
    if isinstance(value, (bytes, bytearray)):
        return f"x'{value.hex()}'"
    # Fallback: treat as string and escape.
    s = str(value)
    s = s.replace("\\", "\\\\").replace("'", "''").replace("\0", "\\0")
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\x1a", "\\Z")
    return f"'{s}'"


def quote_ident(name: str) -> str:
    """Quote a MySQL/MariaDB identifier."""
    return "`" + name.replace("`", "``") + "`"


def qualified_table(schema: Optional[str], table: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(table)}" if schema else quote_ident(table)


# ============================================================================
#  SCHEMA INTROSPECTION
# ============================================================================

def get_columns(conn: pymysql.connections.Connection,
                schema: Optional[str], table: str) -> List[Dict[str, Any]]:
    """Return column metadata: name, type, nullable, is_generated."""
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute(
        """
        SELECT COLUMN_NAME        AS name,
               DATA_TYPE          AS data_type,
               COLUMN_TYPE        AS column_type,
               IS_NULLABLE        AS nullable,
               COLUMN_KEY         AS column_key,
               GENERATION_EXPRESSION AS gen_expr,
               EXTRA              AS extra
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME   = %s
        ORDER BY ORDINAL_POSITION
        """,
        (schema or conn.db.decode() if isinstance(conn.db, bytes)
         else (schema or conn.db), table),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


# ============================================================================
#  DUMP LOGIC
# ============================================================================

@dataclass
class TableTask:
    schema: Optional[str]
    table: str
    where: Optional[str]
    order_by: Optional[str]
    remove_columns: List[str]
    anonymize_columns: List[str]
    obfuscate_columns: List[Dict[str, Any]]


def parse_table_task(raw: Dict[str, Any]) -> TableTask:
    obf: List[Dict[str, Any]] = []
    for c in raw.get("obfuscate_columns", []):
        if isinstance(c, str):
            obf.append({"column": c})
        else:
            obf.append(c)
    return TableTask(
        schema=raw.get("schema"),
        table=raw["table"],
        where=raw.get("where"),
        order_by=raw.get("order_by"),
        remove_columns=list(raw.get("remove_columns", [])),
        anonymize_columns=list(raw.get("anonymize_columns", [])),
        obfuscate_columns=obf,
    )


def select_columns(task: TableTask,
                   meta: List[Dict[str, Any]]) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Pick the columns to SELECT: all minus removed minus generated-virtual
    columns that are not explicitly selected for output."""
    remove = set(task.remove_columns)
    chosen, chosen_meta = [], []
    for col in meta:
        name = col["name"]
        if name in remove:
            continue
        # Skip GENERATED (virtual/stored) columns: cannot be selected via
        # straight SELECT * into an INSERT. (bcp_id is generated -> dropped.)
        if col.get("gen_expr"):
            continue
        chosen.append(name)
        chosen_meta.append(col)
    return chosen, chosen_meta


def build_select(task: TableTask, columns: List[str]) -> str:
    col_sql = ", ".join(quote_ident(c) for c in columns)
    sql = f"SELECT {col_sql} FROM {qualified_table(task.schema, task.table)}"
    if task.where:
        sql += f" WHERE {task.where}"
    if task.order_by:
        sql += f" ORDER BY {task.order_by}"
    return sql


def transform_row(row: Dict[str, Any],
                  task: TableTask,
                  anon: Anonymizer,
                  obf_map: Dict[str, Obfuscator],
                  columns: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for col in columns:
        val = row.get(col)
        if val is None:
            out[col] = None
            continue
        if col in task.anonymize_columns and isinstance(val, str):
            out[col] = anon.forward(val)
        elif col in obf_map:
            # Coerce to Decimal for safe linear math
            try:
                d = val if isinstance(val, Decimal) else Decimal(str(val))
            except Exception:
                # If the value isn't numeric (shouldn't happen for an
                # obfuscate target) keep it untouched.
                out[col] = val
                continue
            out[col] = obf_map[col].forward(d)
        else:
            out[col] = val
    return out


def write_sql(task: TableTask,
              columns: List[str],
              rows: List[Dict[str, Any]],
              out_path: str,
              batch_size: int,
              drop_first: bool,
              create_first: bool,
              meta: List[Dict[str, Any]]) -> int:
    target_table = quote_ident(task.table)
    col_list = "(" + ", ".join(quote_ident(c) for c in columns) + ")"
    written = 0
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"-- Dump of {qualified_table(task.schema, task.table)}\n")
        f.write(f"-- Rows: {len(rows)}\n")
        f.write(f"-- Anonymized columns: {', '.join(task.anonymize_columns) or '(none)'}\n")
        f.write(f"-- Obfuscated columns: {', '.join(o['column'] for o in task.obfuscate_columns) or '(none)'}\n")
        f.write(f"-- Removed columns:   {', '.join(task.remove_columns) or '(none)'}\n\n")
        if drop_first:
            f.write(f"DROP TABLE IF EXISTS {target_table};\n")
        if create_first:
            f.write(build_create_table(task, columns, meta))
            f.write("\n")
        f.write("SET autocommit=0;\nSTART TRANSACTION;\n\n")
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            f.write(f"INSERT INTO {target_table} {col_list} VALUES\n")
            value_lines = []
            for r in batch:
                vals = ", ".join(sql_escape(r.get(c)) for c in columns)
                value_lines.append(f"  ({vals})")
            f.write(",\n".join(value_lines))
            f.write(";\n\n")
            written += len(batch)
        f.write("COMMIT;\n")
    return written


def build_create_table(task: TableTask,
                       columns: List[str],
                       meta: List[Dict[str, Any]]) -> str:
    """Emit a minimal CREATE TABLE for the transformed schema (no removed
    cols, no generated cols). Types are taken from the source column_type."""
    by_name = {m["name"]: m for m in meta}
    lines = []
    for c in columns:
        m = by_name.get(c, {})
        nullable = "" if m.get("nullable") == "NO" else " DEFAULT NULL"
        # column_type already includes e.g. "varchar(64)" / "decimal(18,4)"
        lines.append(f"  {quote_ident(c)} {m.get('column_type', 'text')}{nullable}")
    body = ",\n".join(lines)
    return f"CREATE TABLE {quote_ident(task.table)} (\n{body}\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"


def write_csv(task: TableTask,
              columns: List[str],
              rows: List[Dict[str, Any]],
              out_path: str,
              quoting: int) -> int:
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=quoting)
        writer.writerow(columns)
        for r in rows:
            writer.writerow([r.get(c) for c in columns])
    return len(rows)


# ============================================================================
#  MAIN
# ============================================================================

def connect(cfg: Dict[str, Any]) -> pymysql.connections.Connection:
    c = dict(cfg["connection"])
    ssl = c.pop("ssl", None)
    conn = pymysql.connect(**c)
    if ssl:
        # re-connect with SSL if requested
        conn.close()
        conn = pymysql.connect(ssl=ssl, **c)
    return conn


def process_table(conn: pymysql.connections.Connection,
                  task: TableTask,
                  anon: Anonymizer,
                  out_cfg: Dict[str, Any],
                  obf_defaults: Dict[str, Any]) -> Dict[str, Any]:
    schema = task.schema
    table = task.table
    print(f"→ {schema + '.' if schema else ''}{table}")

    meta = get_columns(conn, schema, table)
    if not meta:
        raise RuntimeError(f"Table not found: {schema}.{table}")

    columns, chosen_meta = select_columns(task, meta)

    # Build obfuscator per column with optional per-column overrides
    obf_map: Dict[str, Obfuscator] = {}
    for spec in task.obfuscate_columns:
        name = spec["column"]
        if name not in columns:
            print(f"  ! obfuscate column '{name}' not in selected columns; skipping")
            continue
        factor = spec.get("factor", obf_defaults["default_factor"])
        rnd = spec.get("round", obf_defaults["default_round"])
        obf_map[name] = Obfuscator.from_cfg(factor, rnd)

    # Warn about anonymized columns that were removed
    for c in task.anonymize_columns:
        if c in task.remove_columns:
            print(f"  ! anonymize column '{c}' is also in remove_columns; it will be dropped")

    sql = build_select(task, columns)
    print(f"  SELECT: {sql}")

    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute(sql)
    raw_rows = cur.fetchall()
    cur.close()
    print(f"  rows fetched: {len(raw_rows)}")

    rows = [transform_row(r, task, anon, obf_map, columns) for r in raw_rows]

    os.makedirs(out_cfg["dir"], exist_ok=True)
    base = f"{schema}_{table}" if schema else table
    fmt = out_cfg.get("format", "sql")
    summary: Dict[str, Any] = {"table": base, "rows": len(rows),
                               "columns": columns, "files": []}

    if fmt in ("sql", "both"):
        p = os.path.join(out_cfg["dir"], f"{base}.sql")
        write_sql(task, columns, rows, p,
                  out_cfg.get("sql_batch_size", 500),
                  out_cfg.get("include_drop_table", False),
                  out_cfg.get("include_create_table", False),
                  meta)
        summary["files"].append(p)
        print(f"  wrote SQL: {p}")
    if fmt in ("csv", "both"):
        p = os.path.join(out_cfg["dir"], f"{base}.csv")
        write_csv(task, columns, rows, p, out_cfg.get("csv_quoting", csv.QUOTE_MINIMAL))
        summary["files"].append(p)
        print(f"  wrote CSV: {p}")

    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="MariaDB anonymizing/obfuscating dumper")
    ap.add_argument("--config", help="JSON config file (overrides built-in CONFIG)")
    args = ap.parse_args(argv)

    cfg = CONFIG
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    anon = Anonymizer(seed=cfg["anonymization"]["seed"])
    obf_defaults = cfg["obfuscation"]
    out_cfg = cfg["output"]

    os.makedirs(out_cfg["dir"], exist_ok=True)

    conn = connect(cfg)
    try:
        results = []
        for t in cfg["tables"]:
            task = parse_table_task(t)
            results.append(process_table(conn, task, anon, out_cfg, obf_defaults))
    finally:
        conn.close()

    print("\nSummary:")
    for r in results:
        print(f"  {r['table']}: {r['rows']} rows -> {', '.join(r['files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())