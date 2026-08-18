"""Property list reading, including embedded NSKeyedArchiver graphs.

iOS stores a great deal of evidence in plists, and a large share of *that* is
wrapped in ``NSKeyedArchiver`` — an object graph flattened into ``$objects``
with ``CF$UID`` back-references.  Reading such a plist naively gives you a list
of integers and no data.  :func:`unarchive` resolves the references and hands
back the real nested structure, which is where things like Safari session
state, notification payloads and app preferences actually live.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.errors import ParserError


def load(path_or_bytes: Union[str, Path, bytes]) -> Any:
    """Load a binary or XML plist."""
    if isinstance(path_or_bytes, (str, Path)):
        data = Path(path_or_bytes).read_bytes()
    else:
        data = path_or_bytes
    if not data:
        return None
    try:
        return plistlib.loads(data)
    except Exception as exc:
        raise ParserError(f"not a readable plist: {exc}") from exc


def is_keyed_archive(obj: Any) -> bool:
    return (isinstance(obj, dict)
            and obj.get("$archiver") in ("NSKeyedArchiver", "NSKeyedUnarchiver")
            and "$objects" in obj and "$top" in obj)


def unarchive(obj: Any, _depth: int = 0) -> Any:
    """Resolve an NSKeyedArchiver graph into plain Python structures."""
    if not is_keyed_archive(obj):
        return obj
    objects: List[Any] = obj["$objects"]
    seen: set[int] = set()

    def resolve(node: Any, depth: int) -> Any:
        if depth > 40:
            return "<max depth>"
        if isinstance(node, plistlib.UID):
            idx = int(node)
            if idx in seen and idx != 0:
                return f"<cycle:{idx}>"
            if not 0 <= idx < len(objects):
                return None
            seen.add(idx)
            try:
                return resolve(objects[idx], depth + 1)
            finally:
                seen.discard(idx)
        if isinstance(node, dict):
            cls = node.get("$class")
            classname = ""
            if isinstance(cls, plistlib.UID):
                cd = objects[int(cls)] if int(cls) < len(objects) else {}
                if isinstance(cd, dict):
                    classname = str(cd.get("$classname", ""))
            # NSArray / NSSet / NSMutableArray
            if classname.startswith(("NSArray", "NSMutableArray", "NSSet",
                                     "NSMutableSet", "NSOrderedSet")):
                return [resolve(v, depth + 1) for v in node.get("NS.objects", [])]
            # NSDictionary
            if classname.startswith(("NSDictionary", "NSMutableDictionary")):
                keys = [resolve(k, depth + 1) for k in node.get("NS.keys", [])]
                vals = [resolve(v, depth + 1) for v in node.get("NS.objects", [])]
                return dict(zip(map(str, keys), vals))
            if classname.startswith(("NSString", "NSMutableString")):
                return node.get("NS.string", "")
            if classname == "NSDate":
                from .timestamps import from_epoch
                return from_epoch(node.get("NS.time"), "apple")
            if classname in ("NSData", "NSMutableData"):
                return node.get("NS.data", b"")
            if classname == "NSURL":
                return str(resolve(node.get("NS.relative"), depth + 1) or "")
            out: Dict[str, Any] = {}
            for k, v in node.items():
                if k in ("$class",):
                    continue
                out[str(k)] = resolve(v, depth + 1)
            if classname:
                out["__class__"] = classname
            return out
        if isinstance(node, (list, tuple)):
            return [resolve(v, depth + 1) for v in node]
        if node == "$null":
            return None
        return node

    top = obj.get("$top", {})
    if isinstance(top, dict):
        if len(top) == 1:
            return resolve(next(iter(top.values())), 0)
        return {str(k): resolve(v, 0) for k, v in top.items()}
    return resolve(top, 0)


def read(path_or_bytes: Union[str, Path, bytes]) -> Any:
    """Load a plist and transparently unarchive it if keyed."""
    obj = load(path_or_bytes)
    return unarchive(obj) if is_keyed_archive(obj) else obj


def flatten(obj: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None,
            max_items: int = 4000) -> Dict[str, Any]:
    """Flatten nested plist data into dotted keys for indexing and display."""
    if out is None:
        out = {}
    if len(out) >= max_items:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, max_items)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj[:200]):
            flatten(v, f"{prefix}[{i}]", out, max_items)
    else:
        if isinstance(obj, bytes):
            obj = f"<{len(obj)} bytes>" if len(obj) > 64 else obj.hex()
        out[prefix or "value"] = obj
    return out
