"""Parser registry and dispatch.

Every artifact parser declares the file *patterns* it recognises and a
``probe`` that confirms a candidate file really is what its name suggests.
Dispatch is content-first: a WhatsApp ``msgstore.db`` renamed to ``notes.db``
is still parsed as WhatsApp, because the probe inspects the schema.

A parser returns ``ParseResult`` — artifacts plus an explicit note about what
it could *not* recover.  That second half matters: "0 messages" and "0 messages
because the database is SQLCipher-encrypted" are different findings.
"""

from __future__ import annotations

import fnmatch
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol

from ..core.models import Artifact

_REGISTRY: List["ParserSpec"] = []


@dataclass
class ParseResult:
    artifacts: List[Artifact] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    deleted_recovered: int = 0
    parser: str = ""
    source: str = ""

    def extend(self, other: "ParseResult") -> None:
        self.artifacts.extend(other.artifacts)
        self.notes.extend(other.notes)
        self.warnings.extend(other.warnings)
        self.deleted_recovered += other.deleted_recovered

    def __len__(self) -> int:
        return len(self.artifacts)


class ParserFn(Protocol):
    def __call__(self, path: Path, ctx: "ParseContext") -> ParseResult: ...


@dataclass
class ParseContext:
    """Everything a parser may need beyond the file itself."""

    evidence_root: Path                     # root of the acquired tree
    platform: str = ""                      # "android" | "ios" | ""
    owner_identifiers: List[str] = field(default_factory=list)
    owner_name: str = "Device owner"
    recover_deleted: bool = True
    carve_confidence: float = 0.45
    store_blob: Optional[Callable[[Path, str], str]] = None   # -> sha256
    log: Optional[Callable[..., Any]] = None
    time_lo: Optional[int] = None
    time_hi: Optional[int] = None
    categories: Optional[List[str]] = None
    # Set only by the dispatch fallback, so the generic survey knows it is
    # being invoked on purpose rather than racing a specific parser.
    force_generic: bool = False
    skip_perceptual_hash: bool = False
    skip_content_sniff: bool = False
    skip_file_hash: bool = False

    def rel(self, path: Path) -> str:
        try:
            return str(Path(path).resolve().relative_to(self.evidence_root.resolve()))
        except Exception:
            return str(path)

    def emit(self, module: str, status: str, message: str, **kw: Any) -> None:
        if self.log:
            self.log(module, status, message, **kw)

    def in_span(self, ts: Optional[int]) -> bool:
        if ts is None:
            return True
        if self.time_lo is not None and ts < self.time_lo:
            return False
        if self.time_hi is not None and ts > self.time_hi:
            return False
        return True

    def wants(self, category) -> bool:
        if not self.categories:
            return True
        value = getattr(category, "value", str(category))
        return value in self.categories

    def is_owner(self, identifier: str) -> bool:
        if not identifier:
            return False
        digits = "".join(c for c in identifier if c.isdigit())
        for own in self.owner_identifiers:
            od = "".join(c for c in own if c.isdigit())
            if od and digits and od[-9:] == digits[-9:]:
                return True
            if own.lower() == identifier.lower():
                return True
        return False


@dataclass
class ParserSpec:
    name: str
    patterns: List[str]
    fn: ParserFn
    platform: str = ""
    priority: int = 50
    probe: Optional[Callable[[Path], bool]] = None
    description: str = ""

    def matches(self, path: Path) -> bool:
        name = path.name.lower()
        full = path.as_posix().lower()
        for pat in self.patterns:
            p = pat.lower()
            matched = (
                fnmatch.fnmatch(name, p)
                or fnmatch.fnmatch(full, p)
                or ("/" in p and (full.endswith("/" + p) or f"/{p}" in full))
            )
            if matched:
                if self.probe:
                    try:
                        return bool(self.probe(path))
                    except Exception:
                        return False
                return True
        return False


def register(name: str, patterns: List[str], platform: str = "",
             priority: int = 50, probe: Optional[Callable[[Path], bool]] = None,
             description: str = "") -> Callable[[ParserFn], ParserFn]:
    """Decorator registering a parser."""
    def deco(fn: ParserFn) -> ParserFn:
        _REGISTRY.append(ParserSpec(name=name, patterns=patterns, fn=fn,
                                    platform=platform, priority=priority,
                                    probe=probe,
                                    description=description or (fn.__doc__ or "").strip()))
        _REGISTRY.sort(key=lambda s: -s.priority)
        return fn
    return deco


def parsers_for(path: Path, platform: str = "") -> List[ParserSpec]:
    ensure_loaded()
    out = []
    for spec in _REGISTRY:
        if spec.platform and platform and spec.platform != platform:
            continue
        if spec.matches(path):
            out.append(spec)
    return out


def all_parsers() -> List[ParserSpec]:
    ensure_loaded()
    return list(_REGISTRY)


FALLBACK_PARSER = "app.generic"


def _decoded_anything(result: "ParseResult") -> bool:
    """Did the parse actually recover content, or only count rows?

    Artifact count is the wrong test. A parser matching a schema variant will
    happily walk every row and emit one artifact each with an empty body and no
    correspondent — twelve messages that say nothing, from nobody. That is not
    a successful parse, it is a silent failure wearing a success's clothes, and
    counting artifacts cannot tell the two apart.
    """
    from ..core.models import Category

    content_categories = {Category.MESSAGE, Category.CALL, Category.CONTACT,
                          Category.CHAT, Category.WEB, Category.NOTE}
    for artifact in result.artifacts:
        if artifact.category not in content_categories:
            return True                    # files, apps, device info: fine
        if (artifact.body or "").strip():
            return True
        if any(p.identifier for p in artifact.participants):
            return True
    return not result.artifacts and False


def dispatch(path: Path, ctx: ParseContext) -> ParseResult:
    """Run every parser that claims ``path``; never let one failure stop a run.

    A specific parser claiming a file suppresses the generic survey, which is
    right when it succeeds and wrong when it does not. A vendor that renames a
    column, or a schema generation nobody has seen, produces a parser that
    matches the filename, recognises nothing inside, and returns empty — and
    because it claimed the file, the fallback that would at least have surveyed
    the tables never runs. The file then appears in no view at all, which is
    indistinguishable from the device not having held it.

    So if every claiming parser comes back empty, the fallback runs anyway.
    """
    result = ParseResult(source=ctx.rel(path))
    claimed = [s for s in parsers_for(path, ctx.platform)]
    specific = [s for s in claimed if s.name != FALLBACK_PARSER]

    for spec in claimed:
        try:
            sub = spec.fn(path, ctx)
            sub.parser = spec.name
            result.extend(sub)
            if sub.artifacts:
                ctx.emit(spec.name, "ok",
                         f"{len(sub.artifacts)} artifacts from {path.name}"
                         + (f" ({sub.deleted_recovered} deleted recovered)"
                            if sub.deleted_recovered else ""))
        except Exception as exc:
            tb = traceback.format_exc(limit=3)
            result.warnings.append(f"{spec.name} failed on {path.name}: {exc}")
            ctx.emit(spec.name, "error", f"{path.name}: {exc}", level="error",
                     traceback=tb)

    if not _decoded_anything(result) and specific:
        # The fallback may already be in `claimed` — it registers a broad
        # pattern — but when it ran there it deferred to the specific parser and
        # returned nothing. This retry is the deliberate second attempt.
        fallback = next((s for s in _REGISTRY if s.name == FALLBACK_PARSER),
                        None)
        if fallback is not None:
            try:
                previous = ctx.force_generic
                ctx.force_generic = True
                try:
                    sub = fallback.fn(path, ctx)
                finally:
                    ctx.force_generic = previous
                sub.parser = fallback.name
                if sub.artifacts:
                    result.extend(sub)
                    result.notes.append(
                        f"{path.name}: claimed by "
                        f"{', '.join(s.name for s in specific)} but decoded "
                        f"nothing, so a generic survey was run instead. The "
                        f"schema is probably a variant this build does not "
                        f"recognise — treat the structure as unconfirmed.")
            except Exception as exc:                      # pragma: no cover
                result.warnings.append(
                    f"{FALLBACK_PARSER} fallback failed on {path.name}: {exc}")
    return result


_LOADED = False


def ensure_loaded() -> None:
    """Guarantee the registry is complete before anything is classified.

    Parser modules register themselves via decorator at import time, so until
    they are imported the registry is partial and ``parsers_for`` under-reports.
    Nothing used to force that import: modules arrived incidentally, pulled in by
    whichever parser happened to run first, which meant the files examined early
    in the very first ingest of a process were matched against a smaller
    registry than the files examined later.

    The effect was a tool whose output depended on how long it had been running.
    The first exhibit in a session could be attributed differently from the
    same exhibit ingested second — reproducible only by accident. This is called
    at every entry point so the registry is always whole.
    """
    global _LOADED
    if _LOADED:
        return
    load_all()
    _LOADED = True


def load_all() -> None:
    """Import every parser module so their decorators run."""
    from . import android, ios, media  # noqa: F401
    from . import antiforensics, platforms  # noqa: F401
    from .android import (accounts, browser, calls, contacts, sms,  # noqa: F401
                          smsbackup, whatsapp, apps, social, vcard,
                          adb_content, dumpsys_comms,
                          system as android_system)
    from .ios import (addressbook, callhistory, notes, safari,      # noqa: F401
                      sms as ios_sms, whatsapp as ios_whatsapp,
                      system as ios_system)
    from .media import exif  # noqa: F401
