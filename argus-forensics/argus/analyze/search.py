"""AQL — the ARGUS Query Language.

XAMN's filter panel is a UI over a boolean expression.  ARGUS exposes that
expression directly, because in practice the useful queries are the ones no
checkbox anticipated:

    category:Messages AND app:WhatsApp AND deleted:true
    "meet me" AND after:2026-03-01
    party:9876543210 AND (category:Calls OR category:Messages)
    has:gps AND before:2026-01-15
    NOT app:Instagram AND tag:relevant

Grammar
-------
::

    query   := or_expr
    or_expr := and_expr (("OR" | "|") and_expr)*
    and_expr:= not_expr (("AND" | "&")? not_expr)*      # AND is implicit
    not_expr:= ("NOT" | "-")? atom
    atom    := "(" or_expr ")" | field ":" value | quoted | bare

Everything compiles down to a parameterised SQL ``WHERE`` clause — user input
never reaches SQL as text, so a query containing an apostrophe is a search
term, not an injection.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.db import ArtifactDB
from ..core.errors import QueryError
from ..core.models import Category, Direction, Recovery
from ..parsers.timestamps import from_iso, span_to_range

FIELDS = {
    "category": "category", "cat": "category",
    "app": "app", "application": "app",
    "type": "subtype", "subtype": "subtype",
    "direction": "direction", "dir": "direction",
    "recovery": "recovery",
    "source": "source_path", "path": "source_path",
    "table": "source_table",
    "body": "body", "text": "body", "message": "body",
}

BOOL_TRUE = {"true", "yes", "1", "y"}


def _fts_escape(value: str) -> str:
    """Prepare a user term for FTS5 MATCH (phrase when it contains spaces)."""
    cleaned = (value or "").replace('"', '""').strip()
    if not cleaned:
        return '""'
    if any(ch in cleaned for ch in " *:"):
        return f'"{cleaned}"'
    if " " in cleaned:
        return f'"{cleaned}"'
    return cleaned


@dataclass
class CompiledQuery:
    where: str
    params: List[Any]
    fts: Optional[str] = None
    description: str = ""

    def bind(self, extra_where: str = "") -> Tuple[str, List[Any]]:
        clauses = [c for c in (self.where, extra_where) if c]
        return (" AND ".join(f"({c})" for c in clauses), list(self.params))


# --------------------------------------------------------------------- lexer
TOKEN_RE = re.compile(r'''
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<not>\bNOT\b|(?<![\w])-(?=\S))
      | (?P<and>\bAND\b|&&?)
      | (?P<or>\bOR\b|\|\|?)
      | (?P<field>[A-Za-z_]+)\s*(?P<op>:|!=|>=|<=|=|>|<)\s*(?P<value>"[^"]*"|'[^']*'|[^\s()]+)
      | (?P<quoted>"[^"]*"|'[^']*')
      | (?P<bare>[^\s()]+)
    )''', re.VERBOSE)


ORDERED_FIELDS = {"confidence", "timestamp", "time", "date"}


@dataclass
class Token:
    kind: str
    value: str = ""
    field: str = ""
    op: str = ":"


def tokenise(text: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            if text[pos].isspace():
                pos += 1
                continue
            raise QueryError(f"cannot parse query at position {pos}: "
                             f"{text[pos:pos+20]!r}")
        pos = m.end()
        gd = m.groupdict()
        if gd["lparen"]:
            tokens.append(Token("lparen"))
        elif gd["rparen"]:
            tokens.append(Token("rparen"))
        elif gd["not"]:
            tokens.append(Token("not"))
        elif gd["and"]:
            tokens.append(Token("and"))
        elif gd["or"]:
            tokens.append(Token("or"))
        elif gd["field"]:
            field = gd["field"].lower()
            operator = gd["op"]
            if operator not in (":", "="):
                # Comparison operators only mean something on ordered fields.
                # Folding `confidence > 0.8` into a substring search would
                # return nothing and look like an empty result rather than a
                # rejected query.
                if field not in ORDERED_FIELDS:
                    raise QueryError(
                        f"'{operator}' is not valid on field '{field}'. "
                        f"Comparison operators apply to "
                        f"{', '.join(sorted(ORDERED_FIELDS))}.")
                tokens.append(Token("term", _unquote(gd["value"]), field,
                                    operator))
            else:
                tokens.append(Token("term", _unquote(gd["value"]), field))
        elif gd["quoted"]:
            tokens.append(Token("term", _unquote(gd["quoted"]), "__phrase__"))
        elif gd["bare"]:
            tokens.append(Token("term", gd["bare"], ""))
    return tokens


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


# -------------------------------------------------------------------- parser
class _Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> Optional[Token]:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Tuple[str, List[Any]]:
        if not self.tokens:
            return "1=1", []
        where, params = self.or_expr()
        if self.peek():
            raise QueryError(f"unexpected token after end of query: "
                             f"{self.peek().value!r}")
        return where, params

    def or_expr(self) -> Tuple[str, List[Any]]:
        where, params = self.and_expr()
        while self.peek() and self.peek().kind == "or":
            self.next()
            rw, rp = self.and_expr()
            where = f"({where}) OR ({rw})"
            params += rp
        return where, params

    def and_expr(self) -> Tuple[str, List[Any]]:
        where, params = self.not_expr()
        while True:
            tok = self.peek()
            if tok is None or tok.kind in ("or", "rparen"):
                break
            if tok.kind == "and":
                self.next()
                tok = self.peek()
                if tok is None:
                    raise QueryError("query ends with a dangling AND")
            rw, rp = self.not_expr()
            where = f"({where}) AND ({rw})"
            params += rp
        return where, params

    def not_expr(self) -> Tuple[str, List[Any]]:
        if self.peek() and self.peek().kind == "not":
            self.next()
            where, params = self.not_expr()
            return f"NOT ({where})", params
        return self.atom()

    def atom(self) -> Tuple[str, List[Any]]:
        tok = self.peek()
        if tok is None:
            raise QueryError("unexpected end of query")
        if tok.kind == "lparen":
            self.next()
            where, params = self.or_expr()
            if not (self.peek() and self.peek().kind == "rparen"):
                raise QueryError("unbalanced parenthesis")
            self.next()
            return f"({where})", params
        if tok.kind == "term":
            self.next()
            return compile_term(tok)
        raise QueryError(f"unexpected {tok.kind} token in query")


# ---------------------------------------------------------------- term rules
def compile_term(tok: Token) -> Tuple[str, List[Any]]:
    field, value = tok.field, tok.value

    if field in ("", "__phrase__"):
        fts_q = _fts_escape(value)
        return ("artifact_id IN (SELECT artifact_id FROM artifact_fts "
                "WHERE artifact_fts MATCH ?)"), [fts_q]

    if field in FIELDS:
        column = FIELDS[field]
        if column == "category":
            return "category = ?", [Category.coerce(value).value]
        if column == "direction":
            v = value.lower()
            if v not in {d.value for d in Direction}:
                raise QueryError(
                    f"unknown direction {value!r}; expected one of "
                    f"{sorted(d.value for d in Direction)}")
            return "direction = ?", [v]
        if column == "recovery":
            return "recovery = ?", [value.lower()]
        if column == "body":
            fts_q = f"body:{_fts_escape(value)}"
            return ("artifact_id IN (SELECT artifact_id FROM artifact_fts "
                    "WHERE artifact_fts MATCH ?)"), [fts_q]
        return f"{column} LIKE ?", [f"%{value}%"]

    if field in ("party", "contact", "number", "with"):
        digits = "".join(c for c in value if c.isdigit())
        norm = digits[-10:] if len(digits) >= 7 else value.lower()
        return ("artifact_id IN (SELECT artifact_id FROM participant WHERE "
                "normalised = ? OR identifier LIKE ? OR display_name LIKE ?)",
                [norm, f"%{value}%", f"%{value}%"])

    if field == "tag":
        if value.lower() in ("any", "*"):
            return "artifact_id IN (SELECT artifact_id FROM tag)", []
        return ("artifact_id IN (SELECT artifact_id FROM tag WHERE name = ?)",
                [value])

    if field == "deleted":
        want = value.lower() in BOOL_TRUE
        clause = "recovery <> ?" if want else "recovery = ?"
        return clause, [Recovery.ALLOCATED.value]

    if field in ("after", "since", "from"):
        ts = _parse_time(value)
        return "timestamp >= ?", [ts]

    if field in ("before", "until", "to"):
        ts = _parse_time(value, end_of_day=True)
        return "timestamp <= ?", [ts]

    if field == "span":
        lo, hi = span_to_range(value)
        if lo is None and hi is None:
            return "1=1", []
        clauses, params = [], []
        if lo is not None:
            clauses.append("timestamp >= ?")
            params.append(lo)
        if hi is not None:
            clauses.append("timestamp <= ?")
            params.append(hi)
        return " AND ".join(clauses), params

    if field == "has":
        v = value.lower()
        if v in ("gps", "location", "coords"):
            return "latitude IS NOT NULL AND longitude IS NOT NULL", []
        if v in ("blob", "media", "attachment", "file"):
            return "blob_sha256 <> ''", []
        if v in ("time", "timestamp", "date"):
            return "timestamp IS NOT NULL", []
        if v in ("body", "text"):
            return "body <> ''", []
        raise QueryError(
            f"unknown has: value {value!r}; try gps, media, time or body")

    if field == "confidence":
        # `confidence > 0.8` carries its operator on the token; the older
        # `confidence:>0.8` carries it inside the value. Both are accepted, and
        # an explicit operator must not be quietly widened — reporting records
        # at exactly 0.8 for a query that asked for more than 0.8 is a small
        # error that compounds into a wrong count in a report.
        if tok.op in (">", "<", ">=", "<=", "!="):
            op, num = tok.op, value.strip()
        else:
            op, num = _split_op(value)
        if op == "!=":
            op = "<>"
        try:
            threshold = float(num)
        except ValueError:
            raise QueryError(
                f"confidence expects a number, got {num!r}")
        return f"confidence {op} ?", [threshold]

    if field in ("timestamp", "time", "date") and tok.op in (">", "<", ">=",
                                                             "<="):
        return f"timestamp {tok.op} ?", [_parse_time(value,
                                                     end_of_day=tok.op == "<=")]

    if field in ("id", "artifact"):
        return "artifact_id = ?", [value]

    raise QueryError(
        f"unknown field {field!r}. Known fields: "
        f"{', '.join(sorted(set(list(FIELDS) + ['party', 'tag', 'deleted', 'after', 'before', 'span', 'has', 'confidence'])))}")


def _split_op(value: str) -> Tuple[str, str]:
    m = re.match(r"^(>=|<=|>|<|=)?\s*([0-9.]+)$", value.strip())
    if not m:
        raise QueryError(f"expected a numeric comparison, got {value!r}")
    return (m.group(1) or ">="), m.group(2)


def _parse_time(value: str, end_of_day: bool = False) -> int:
    ts = from_iso(value)
    if ts is None:
        raise QueryError(
            f"cannot parse date {value!r}; use YYYY-MM-DD or "
            f"YYYY-MM-DDTHH:MM:SS")
    if end_of_day and len(value.strip()) <= 10:
        ts += 86_400_000_000 - 1
    return ts


# ----------------------------------------------------------------- public API
def compile_query(text: str) -> CompiledQuery:
    """Compile AQL text into a parameterised SQL WHERE clause."""
    text = (text or "").strip()
    if not text:
        return CompiledQuery("1=1", [], description="all artifacts")
    where, params = _Parser(tokenise(text)).parse()
    return CompiledQuery(where=where, params=params, description=text)


def search(db: ArtifactDB, query: str, limit: int = 500, offset: int = 0,
           order: str = "timestamp DESC") -> Dict[str, Any]:
    """Run an AQL query against a container database."""
    compiled = compile_query(query)
    total = db.count(compiled.where, compiled.params)
    rows = list(db.iter_artifacts(compiled.where, compiled.params,
                                  order=order, limit=limit, offset=offset))
    return {
        "query": query,
        "sql_where": compiled.where,
        "total": total,
        "returned": len(rows),
        "offset": offset,
        "artifacts": rows,
    }


def suggest(db: ArtifactDB) -> Dict[str, List[str]]:
    """Values an analyst can actually filter on in *this* case."""
    return {
        "category": list(db.category_counts()),
        "app": list(db.app_counts())[:40],
        "recovery": list(db.recovery_counts()),
        "tag": [t["name"] for t in db.tag_names()],
        "examples": [
            'category:Messages AND deleted:true',
            'app:WhatsApp AND after:2026-01-01',
            '"meet me" OR "the package"',
            'party:9876543210',
            'has:gps AND category:"Files & Media"',
            'category:Calls AND direction:missed',
            'NOT app:Instagram AND tag:relevant',
        ],
    }
