"""Android accounts, Wi-Fi networks and device identity.

These populate the manual's *Security*, *Networks* and *Device info*
categories.  Wi-Fi history in particular is a location proxy: an SSID with a
known physical location places the handset there, often long after any GPS
record has been purged.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...core.models import Artifact, Category, Recovery
from ..common import any_table_probe, as_int, as_text, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess


@register(
    name="android.accounts",
    patterns=["accounts.db", "accounts_ce.db", "accounts_de.db"],
    platform="android", priority=70,
    probe=any_table_probe(("accounts",)),
    description="Android AccountManager registry (signed-in accounts)",
)
def parse_accounts(path: Path, ctx: ParseContext) -> ParseResult:
    """Android account registry."""
    res = ParseResult(parser="android.accounts", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        for row, recovery, conf in rows_with_deleted(db, "accounts", ctx):
            name = as_text(pick(row, "name", default=""))
            atype = as_text(pick(row, "type", default=""))
            if not name:
                continue
            art = Artifact(
                category=Category.ACCOUNT, subtype="Signed-in account",
                body=f"{name} ({atype})", app=atype or "AccountManager",
                source_path=ctx.rel(path), source_table="accounts",
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={"account_name": name, "account_type": atype,
                            "previous_name": as_text(pick(row, "previous_name",
                                                          default=""))},
            )
            art.add_participant(name, "", role="owner", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


WIFI_ENTRY = re.compile(
    r'ssid="?([^"\n]+)"?.*?(?:psk|key_mgmt)\s*=\s*"?([^"\n]+)"?',
    re.IGNORECASE | re.DOTALL)


@register(
    name="android.wifi",
    patterns=["wpa_supplicant.conf", "WifiConfigStore.xml",
              "wifiConfigStore.xml", "*.wificonfig"],
    platform="android", priority=60,
    description="Configured Wi-Fi networks",
)
def parse_wifi(path: Path, ctx: ParseContext) -> ParseResult:
    """Configured Wi-Fi networks."""
    res = ParseResult(parser="android.wifi", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    entries = []
    if path.suffix.lower() == ".xml":
        for m in re.finditer(
                r'<string name="SSID">&quot;?([^<&]+)&quot;?</string>', text):
            entries.append((m.group(1), ""))
        for m in re.finditer(r'<string name="SSID">"?([^"<]+)"?</string>', text):
            entries.append((m.group(1), ""))
    else:
        for block in re.split(r"\bnetwork\s*=\s*\{", text)[1:]:
            m = re.search(r'ssid\s*=\s*"?([^"\n]+)"?', block)
            k = re.search(r'key_mgmt\s*=\s*([^\s\n]+)', block)
            if m:
                entries.append((m.group(1).strip(), k.group(1) if k else ""))

    seen = set()
    for ssid, keymgmt in entries:
        if not ssid or ssid in seen:
            continue
        seen.add(ssid)
        art = Artifact(
            category=Category.NETWORK, subtype="Wi-Fi network",
            body=ssid, app="Android Wi-Fi", source_path=ctx.rel(path),
            attributes={"ssid": ssid, "key_management": keymgmt,
                        "note": "Configured network — indicates the device has "
                                "been within range of this access point."},
        )
        res.artifacts.append(art)
    return res


@register(
    name="android.deviceinfo",
    patterns=["build.prop", "getprop.txt", "device_info.txt"],
    platform="android", priority=90,
    description="Device build properties",
)
def parse_buildprop(path: Path, ctx: ParseContext) -> ParseResult:
    """Android build properties."""
    res = ParseResult(parser="android.deviceinfo", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res
    props = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]$", line)
        if m:
            props[m.group(1)] = m.group(2)
        elif "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()
    if not props:
        return res
    interesting = {k: v for k, v in props.items()
                   if k.startswith(("ro.product", "ro.build", "ro.serialno",
                                    "ro.boot", "ro.crypto", "persist.sys"))}
    art = Artifact(
        category=Category.DEVICE, subtype="Build properties",
        body=" ".join(filter(None, [props.get("ro.product.manufacturer", ""),
                                    props.get("ro.product.model", ""),
                                    "Android " + props.get(
                                        "ro.build.version.release", "")])),
        app="Android", source_path=ctx.rel(path),
        attributes={"properties": interesting,
                    "android_version": props.get("ro.build.version.release", ""),
                    "security_patch": props.get("ro.build.version.security_patch", ""),
                    "serial": props.get("ro.serialno", ""),
                    "build_fingerprint": props.get("ro.build.fingerprint", ""),
                    "encryption_state": props.get("ro.crypto.state", "")},
    )
    res.artifacts.append(art)
    return res
