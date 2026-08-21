"""ARGUS command line interface.

Mirrors the lab manual step for step::

    argus devices                       # §5.4  detect connected handsets
    argus manual search "iPhone 12"     # §5.1  Step 1 — search the manual
    argus manual show "iPhone 12 mini"  # §5.1  Step 2 — capability overview
    argus case new --investigator ...   # §5.2  Steps 3–5
    argus case show <case>              # §5.3  Case Overview
    argus exhibit add <case> EXH-001    #       register the seized item
    argus acquire <case> ...            # §5.5–5.9  Steps 8–13
    argus verify <container>            # §7  precaution 5 — integrity
    argus analyze <container>           # §6  Steps 14–20 (opens the UI)
    argus query <container> "<aql>"     #       headless search
    argus report <container> ...        # §6.8  Step 21

Built on argparse — no third-party CLI framework — so it runs on a locked-down
forensic workstation with nothing but a Python install.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .core.case import Case, Exhibit, discover_cases, generate_case_id
from .core.errors import ArgusError
from .core.models import Category

ALL_CATEGORIES = [c.value for c in Category]


# --------------------------------------------------------------------- output
class Out:
    """Minimal ANSI-aware console output."""

    def __init__(self, use_colour: bool = True, quiet: bool = False):
        self.colour = use_colour and sys.stdout.isatty()
        self.quiet = quiet

    def _c(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.colour else text

    def title(self, text: str) -> None:
        if self.quiet:
            return
        print(f"\n{self._c(text, '1;36')}\n{self._c('─' * min(len(text), 70), '90')}")

    def kv(self, key: str, value: Any, width: int = 22) -> None:
        if not self.quiet:
            print(f"  {self._c(key.ljust(width), '90')} {value}")

    def ok(self, text: str) -> None:
        if not self.quiet:
            print(f"  {self._c('✓', '32')} {text}")

    def warn(self, text: str) -> None:
        print(f"  {self._c('!', '33')} {text}", file=sys.stderr)

    def err(self, text: str) -> None:
        print(f"  {self._c('✗', '31')} {text}", file=sys.stderr)

    def info(self, text: str) -> None:
        if not self.quiet:
            print(f"  {text}")

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[Any]],
              limit: int = 80) -> None:
        if self.quiet or not rows:
            if not rows and not self.quiet:
                print("  (none)")
            return
        rows = [[str(c if c is not None else "") for c in r] for r in rows[:limit]]
        widths = [max(len(str(h)), *(len(r[i]) for r in rows))
                  for i, h in enumerate(headers)]
        widths = [min(w, 52) for w in widths]
        print("  " + self._c("  ".join(
            str(h)[:w].ljust(w) for h, w in zip(headers, widths)), "1;90"))
        for r in rows:
            print("  " + "  ".join(c[:w].ljust(w) for c, w in zip(r, widths)))


# ------------------------------------------------------------------ commands
def cmd_devices(args, out: Out) -> int:
    from .devices.detect import detect_all
    result = detect_all()
    out.title("Connected devices")
    if not result["devices"]:
        out.warn("No devices detected.")
        for d in result["diagnostics"]:
            out.info(d)
        out.title("Toolchain")
        for name, info in result["toolchain"].items():
            status = "available" if info["available"] else "NOT INSTALLED"
            out.kv(name, f"{status}  {info.get('path') or info['install_hint']}")
        return 1
    for d in result["devices"]:
        out.title(f"{d['name'] or d['serial']}")
        for k in ("serial", "make", "model", "os_family", "os_version",
                  "build_id", "chipset", "imei", "iccid", "phone_number",
                  "lock_state", "trusted", "rooted", "encrypted", "battery"):
            if d.get(k) not in (None, "", False) or k in ("rooted", "trusted"):
                out.kv(k, d[k])
        if d.get("raw", {}).get("hint"):
            out.warn(d["raw"]["hint"])
    return 0


def cmd_manual(args, out: Out) -> int:
    from .devices.manual import DeviceManual
    manual = DeviceManual()
    if args.manual_action == "search":
        hits = manual.search(args.query, limit=args.limit)
        out.title(f"Device manual — {len(hits)} match(es) for {args.query!r}")
        out.table(["Device", "OS", "Chipset", "Released", "Connector"],
                  [[p.name, f"{p.os_family} {p.os_versions}", p.chipset,
                    p.released, p.connector] for p in hits])
        if not hits:
            out.warn("Not in the manual. Do not attempt extraction on an "
                     "unverified device (manual §7, precaution 1).")
            return 1
        return 0

    if args.manual_action == "show":
        from .core.errors import DeviceNotSupportedError
        try:
            data = manual.overview(args.query)
        except DeviceNotSupportedError:
            # Not catalogued. Derive a profile from what actually governs
            # acquisition rather than leaving the examiner with nothing.
            result = manual.profile_or_inference(
                args.query, chipset=getattr(args, "chipset", "") or "",
                os_family=getattr(args, "os", "") or "",
                os_version=getattr(args, "os_version", "") or "")
            inference = result["inference"]
            out.title(f"{args.query} — not in the device manual")
            out.warn("Profile below is INFERRED from chipset and OS release. "
                     "It has not been measured on this model.")
            out.kv("confidence", f"{result['confidence']:.2f} (a catalogued "
                                 f"entry scores 1.00)")
            out.kv("chipset family", inference["chipset_family"] or "unrecognised")
            out.kv("encryption", inference["encryption"])
            out.title("Candidate methods by lock state")
            for state, methods in inference["methods"].items():
                out.kv(state, ", ".join(methods))
            out.title("Reasoning")
            for line in inference["reasoning"]:
                out.info(f"- {line}")
            if result["similar_catalogued"]:
                out.title("Catalogued devices with similar names")
                out.info(", ".join(result["similar_catalogued"]))
                out.warn("These are name matches only. Do not adopt one of "
                         "these matrices for the device in hand.")
            out.warn(inference["caveat"])
            return 0
        dev = data["device"]
        out.title(f"{dev['name']} — device overview")
        for k in ("os_family", "os_versions", "chipset", "codename",
                  "released", "connector"):
            out.kv(k.replace("_", " "), dev.get(k) or "—")
        if dev.get("aliases"):
            out.kv("aliases", ", ".join(dev["aliases"]))
        if dev.get("notes"):
            out.kv("notes", dev["notes"])
        out.title("Capability overview")
        for row in data["capability_overview"]:
            methods = row["methods"]
            if not methods:
                out.kv(row["label"], "no supported method")
                continue
            out.kv(row["label"],
                   ", ".join(f"{m['label']} [{m['risk']}]" for m in methods))
            for m in methods:
                if m.get("note"):
                    out.info(f"      └ {m['method']}: {m['note']}")
        out.warn(data["warning"])
        return 0

    out.table(["Device", "OS", "Chipset"],
              [[p.name, p.os_family, p.chipset] for p in manual.profiles])
    return 0


def cmd_case(args, out: Out) -> int:
    if args.case_action == "new":
        case = Case.create(
            args.dir, case_id=args.id, investigator=args.investigator,
            organisation=args.organisation, description=args.description,
            password=args.password)
        out.title("Case created")
        out.kv("Case ID", case.case_id)
        out.kv("Location", case.root)
        out.kv("Investigator", args.investigator or "—")
        out.kv("Password protected", "yes" if args.password else "no")
        out.ok("Next: register the exhibit with  argus exhibit add "
               f"{case.root} <EXHIBIT-ID>")
        return 0

    if args.case_action == "list":
        cases = discover_cases(args.dir)
        out.title(f"Cases under {args.dir}")
        out.table(["Case ID", "Created", "Investigator", "Exhibits",
                   "Status", "Locked"],
                  [[c["case_id"], c["created_at"][:19], c["investigator"],
                    c["exhibits"], c["status"], "yes" if c["protected"] else ""]
                   for c in cases])
        return 0

    if args.case_action == "show":
        case = Case.open(args.path, password=args.password)
        ov = case.overview()
        if args.json:
            print(json.dumps(ov, indent=2, default=str))
            return 0
        out.title(f"Case Overview — {ov['case_id']}")
        for k in ("created_at", "investigator", "organisation", "status",
                  "location", "total_artifacts"):
            out.kv(k.replace("_", " "), ov[k])
        out.kv("audit entries", f"{ov['audit_entries']} "
               f"({'chain valid' if ov['audit_chain_valid'] else 'CHAIN BROKEN'})")
        if not ov["audit_chain_valid"]:
            for p in ov["audit_problems"][:5]:
                out.err(p)

        out.title("Exhibits")
        out.table(["Exhibit", "Make", "Model", "IMEI", "Isolation"],
                  [[e["exhibit_id"], e["make"], e["model"], e["imei"],
                    e["isolation"]] for e in ov["exhibits"]])

        out.title("Extractions")
        out.table(["File", "Exhibit", "Method", "Device", "Artifacts",
                   "Size", "Status"],
                  [[x["name"], x["exhibit_id"], x["method"], x["device"],
                    f"{x['artifacts']:,}", _human(x["size_bytes"]), x["status"]]
                   for x in ov["extractions"]])
        return 0

    return 1


def cmd_exhibit(args, out: Out) -> int:
    case = Case.open(args.case, password=args.password)
    exhibit = case.add_exhibit(Exhibit(
        exhibit_id=args.exhibit_id, description=args.description,
        make=args.make, model=args.model, imei=args.imei, serial=args.serial,
        phone_number=args.number, seized_at=args.seized_at,
        seized_by=args.seized_by, seized_from=args.seized_from,
        condition=args.condition, isolation=args.isolation))
    out.title("Exhibit registered")
    for k, v in exhibit.as_dict().items():
        if v:
            out.kv(k.replace("_", " "), v)
    if not args.isolation:
        out.warn("No isolation method recorded. Manual §7 precaution 2: place "
                 "the device in airplane mode or a Faraday pouch to prevent a "
                 "remote wipe.")
    return 0


def cmd_acquire(args, out: Out) -> int:
    from .acquire.engine import AcquisitionEngine, AcquisitionPlan
    from .devices.detect import require_device

    case = Case.open(args.case, password=args.password)
    categories = (ALL_CATEGORIES if args.categories in (None, "all")
                  else [c.strip() for c in args.categories.split(",")])

    device = None
    if args.method not in ("import", "sim", "cloud"):
        device = require_device(args.serial)
        out.ok(f"Device: {device.name} ({device.os_family} "
               f"{device.os_version}, serial {device.serial})")

    plan = AcquisitionPlan(
        method=args.method, time_span=args.span, categories=categories,
        operator=args.operator, exhibit_id=args.exhibit,
        lock_state=args.lock_state,
        device_name=args.device or (device.name if device else ""),
        serial=args.serial,
        source_path=Path(args.source) if args.source else None,
        backup_password=args.backup_password,
        recover_deleted=not args.no_carve,
        carve_confidence=args.carve_confidence,
        owner_identifiers=[s.strip() for s in (args.owner or "").split(",")
                           if s.strip()],
        owner_name=args.owner_name, notes=args.notes,
        resume=bool(args.resume),
        resume_container=args.resume_container or None,
        turbo=bool(args.turbo),
        physical_full=bool(getattr(args, "physical_full", False)),
        file_timeout=int(getattr(args, "file_timeout", 180)),
        god=bool(getattr(args, "god", False)))

    def progress(entry):
        level = entry.get("level", "info")
        line = (f"  {entry['ts'][11:23]}  {entry['module'][:18].ljust(18)} "
                f"{entry['status'][:9].ljust(9)} {entry['message']}")
        if level == "error":
            out.err(line.strip())
        elif level == "warning":
            out.warn(line.strip())
        elif not out.quiet:
            print(line)

    engine = AcquisitionEngine(case, progress=progress)
    out.title(f"Extraction — {args.method}")
    out.kv("Case", case.case_id)
    out.kv("Exhibit", args.exhibit)
    out.kv("Operator", args.operator)
    out.kv("Time span", args.span)
    out.kv("Categories", f"{len(categories)}/{len(ALL_CATEGORIES)}")
    out.kv("Recover deleted", "no" if args.no_carve else "yes")
    if args.turbo:
        out.kv("Turbo", "yes — fastest preset (no carve, parallel pulls)")
    print()

    report = engine.run(plan, device=device)

    out.title(f"Extraction {report.status}")
    out.kv("Container", report.container)
    out.kv("Duration", f"{report.duration_seconds}s")
    out.kv("Files acquired", f"{report.files_acquired:,}")
    out.kv("Bytes acquired", _human(report.bytes_acquired))
    out.kv("Artifacts", f"{report.artifacts:,}")
    out.kv("Deleted recovered", f"{report.deleted_recovered:,}")
    if report.seal:
        out.kv("Seal", report.seal.get("container_seal", "")[:48])
    if report.categories:
        out.title("Categories")
        out.table(["Category", "Count"],
                  sorted(report.categories.items(), key=lambda kv: -kv[1]))
    for w in report.warnings[:15]:
        out.warn(w)
    for f in report.integrity_failures:
        out.err(f"INTEGRITY: {f}")
    if report.artifacts:
        out.ok(f"Analyse it:  argus analyze {report.container}")
    return 0 if report.status.startswith("Completed") else 1


def cmd_acquire_batch(args, out: Out) -> int:
    import json as _json

    from .acquire.batch import (BatchAcquisitionEngine, BatchAcquisitionPlan,
                                BatchDeviceSpec, build_specs_from_connected)

    case = Case.open(args.case, password=args.password)
    categories = (ALL_CATEGORIES if args.categories in (None, "all")
                  else [c.strip() for c in args.categories.split(",")])

    specs: List[BatchDeviceSpec] = []
    if args.plan:
        raw = _json.loads(Path(args.plan).read_text(encoding="utf-8"))
        queue = raw.get("devices", raw if isinstance(raw, list) else [])
        for entry in queue:
            specs.append(BatchDeviceSpec(**entry))
    elif args.all_connected:
        specs = build_specs_from_connected(
            method=args.method, prefix=args.exhibit_prefix)
    else:
        raise ArgusError(
            "batch extraction needs --all-connected or --plan <devices.json>")

    if not specs:
        raise ArgusError("batch queue is empty — no ready devices connected")

    plan = BatchAcquisitionPlan(
        operator=args.operator,
        devices=specs,
        time_span=args.span,
        categories=categories,
        stop_on_error=bool(args.stop_on_error),
        auto_register_exhibits=not args.no_auto_exhibit,
        exhibit_prefix=args.exhibit_prefix,
        recover_deleted=not args.no_carve,
        carve_confidence=args.carve_confidence,
        owner_identifiers=[s.strip() for s in (args.owner or "").split(",")
                           if s.strip()],
        owner_name=args.owner_name,
        turbo=bool(args.turbo),
    )
    plan.validate()

    def progress(entry):
        level = entry.get("level", "info")
        extra = ""
        if entry.get("batch_current") and entry.get("batch_total"):
            extra = (f" [{entry['batch_current']}/{entry['batch_total']}]")
        line = (f"  {entry['ts'][11:23]}  {entry['module'][:18].ljust(18)} "
                f"{entry['status'][:9].ljust(9)} {entry['message']}{extra}")
        if level == "error":
            out.err(line.strip())
        elif level == "warning":
            out.warn(line.strip())
        elif not out.quiet:
            print(line)

    engine = BatchAcquisitionEngine(case, progress=progress)
    out.title(f"Batch extraction — {len(specs)} device(s)")
    out.kv("Case", case.case_id)
    out.kv("Operator", args.operator)
    out.kv("Method", args.method)
    out.kv("Stop on error", "yes" if args.stop_on_error else "no")
    print()

    report = engine.run(plan)

    out.title("Batch complete")
    out.kv("Succeeded", str(report.completed))
    out.kv("Failed", str(report.failed))
    out.kv("Skipped", str(report.skipped))
    out.table(["Exhibit", "Serial", "Status", "Artifacts", "Container"],
              [(r.exhibit_id, r.serial[:12], r.status, str(r.artifacts),
                Path(r.container).name if r.container else "—")
               for r in report.results])
    for r in report.results:
        if r.error:
            out.warn(f"{r.exhibit_id or r.serial}: {r.error}")
    return 0 if report.failed == 0 else 1


def cmd_verify(args, out: Out) -> int:
    from .core.container import EvidenceContainer
    exit_code = 0
    for path in args.containers:
        container = EvidenceContainer(Path(path), mode="r")
        result = container.verify(deep=not args.quick)
        out.title(f"Verification — {Path(path).name}")
        out.kv("Sealed", result["sealed"])
        out.kv("Blobs checked", f"{result['blobs_checked']:,}")
        out.kv("Audit entries", result["audit_entries"])
        out.kv("Audit chain", "valid" if result["audit_chain_valid"]
               else "BROKEN")
        out.kv("Depth", "full re-hash" if result["deep"] else "quick")
        if result["ok"]:
            out.ok("VERIFIED — evidence matches its recorded hashes.")
        else:
            out.err("VERIFICATION FAILED")
            for p in result["problems"]:
                out.err(p)
            exit_code = 4
        # Enhanced: also verify MTP/ADB acquisition manifests where present
        try:
            from .acquire.engine import verify_acquisition
            mres = verify_acquisition(Path(path))
            if mres.get("manifests"):
                for name, mv in mres["manifests"].items():
                    if not mv.get("ok"):
                        out.err(f"Manifest {name}: {mv.get('counts')}")
                        for a in mv.get("altered", [])[:3]:
                            out.err(f"  ALTERED {a.get('path')}")
                        for mi in mv.get("missing", [])[:3]:
                            out.err(f"  MISSING {mi}")
                        exit_code = 4
                    elif mv.get("counts", {}).get("unchanged", 0) > 0:
                        out.ok(f"Manifest {name}: {mv['counts']['unchanged']} file(s) verified")
        except Exception:
            pass
        container.close()
    return exit_code


def cmd_analyze(args, out: Out) -> int:
    from .server.app import serve
    serve([Path(c) for c in args.containers], host=args.host, port=args.port,
          open_browser=not args.no_browser, deep_verify=args.deep_verify,
          owner_label=args.owner_name, tz_offset_minutes=args.tz)
    return 0


def cmd_app(args, out: Out) -> int:
    """Start the full workbench — the one-click application entry point."""
    from .server.workbench import serve
    serve(workspace=Path(args.workspace).expanduser(), port=args.port,
          open_browser=not args.no_browser, quiet=args.quiet)
    return 0


def cmd_query(args, out: Out) -> int:
    from .analyze.session import AnalysisSession
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        result = session.query(args.aql, limit=args.limit,
                               order=args.order)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0
        out.title(f"{result['returned']:,} of {result['total']:,} artifacts")
        out.table(["Time", "Category", "Type", "Party", "Content", "State"],
                  [[a["timestamp_iso"][:19], a["category"], a["subtype"],
                    "; ".join(p["label"] for p in a["parties"]
                              if not p["is_owner"])[:28],
                    (a["body"] or "").replace("\n", " ")[:60],
                    a["recovery"] if a["is_deleted"] else ""]
                   for a in result["artifacts"]], limit=args.limit)
        if not session.integrity_ok:
            out.err("Container integrity verification FAILED — see "
                    "`argus verify`.")
    return 0


def cmd_keywords(args, out: Out) -> int:
    from .analyze.session import AnalysisSession
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        result = session.scan_keywords(
            text=args.terms.replace(",", "\n") if args.terms else "",
            path=args.file, per_term=args.per_term)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0
        out.title(f"Keyword list — {result['matched']} of {result['terms']} matched")
        out.table(["Hits", "Term"],
                  [[h["total"], h["term"]] for h in result["hits"]],
                  limit=500)
        if not session.integrity_ok:
            out.err("Container integrity verification FAILED — see "
                    "`argus verify`.")
    return 0


def cmd_stats(args, out: Out) -> int:
    from .analyze.session import AnalysisSession
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        st = session.statistics(args.aql)
        if args.json:
            print(json.dumps(st, indent=2, default=str))
            return 0
        out.title("Statistics")
        for k in ("total_artifacts", "timestamped", "undated",
                  "first_activity", "last_activity", "span_days",
                  "deleted_recovered", "total_call_display",
                  "geolocated_artifacts"):
            out.kv(k.replace("_", " "), st[k])
        out.title("Categories")
        out.table(["Category", "Count"], list(st["categories"].items()))
        out.title("Applications")
        out.table(["Application", "Count"],
                  list(st["applications"].items())[:20])
        if st["anomalies"]:
            out.title("Timestamp anomalies")
            for a in st["anomalies"][:10]:
                out.warn(f"[{a['severity']}] {a['reason']} — {a['summary'][:60]}")
        if st["gaps"]:
            out.title("Longest silences")
            out.table(["From", "To", "Hours"],
                      [[g["from_iso"][:19], g["to_iso"][:19], g["hours"]]
                       for g in st["gaps"][:8]])
    return 0


def cmd_graph(args, out: Out) -> int:
    from .analyze.session import AnalysisSession
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        data = session.connections(args.scope, min_weight=args.min_weight)
        if args.graphml:
            from .analyze.graph import ConnectionGraph
            key = f"{args.scope}:{args.min_weight}"
            graph = session._graph_cache[key]
            Path(args.graphml).write_text(graph.to_graphml(), encoding="utf-8")
            out.ok(f"GraphML written to {args.graphml}")
        if args.json:
            print(json.dumps(data, indent=2, default=str))
            return 0
        out.title(f"Connection view — {args.scope}")
        out.kv("Parties", data["stats"]["total_nodes"])
        out.kv("Links", data["stats"]["total_edges"])
        out.kv("Clusters", data["stats"]["components"])
        out.title("Top contacts")
        out.table(["Party", "Artifacts", "Calls", "Messages", "Parties",
                   "Apps"],
                  [[n["label"], n["artifact_count"], n["calls"], n["messages"],
                    n["degree"], ", ".join(list(n["apps"])[:3])]
                   for n in data["top_contacts"]])
        if data["brokers"]:
            out.title("Brokers (bridge otherwise separate clusters)")
            out.table(["Party", "Betweenness", "Parties"],
                      [[n["label"], n["betweenness"], n["degree"]]
                       for n in data["brokers"]])
        if data["one_way"]:
            out.title("One-way links (traffic in a single direction)")
            labels = {n["key"]: n["label"] for n in data["nodes"]}
            out.table(["A", "B", "Artifacts"],
                      [[labels.get(e["source"], e["source"]),
                        labels.get(e["target"], e["target"]),
                        e["artifact_count"]] for e in data["one_way"]])
    return 0


def cmd_intel(args, out: Out) -> int:
    """Investigative findings — the lead sheet."""
    from .analyze.session import AnalysisSession
    owner = [x.strip() for x in (args.owner or "").split(",") if x.strip()]
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        result = session.intelligence(owner)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    f = result["findings"]
    out.title(f"Investigative findings — {f['count']} lead(s) from "
              f"{result['artifacts_analysed']:,} artifacts")
    sev = f["by_severity"]
    out.kv("severity", "  ".join(f"{k}={v}" for k, v in sev.items() if v))
    out.kv("rules run", f["rules_run"])
    out.kv("exhibits", ", ".join(result["exhibits"]))

    for item in f["findings"]:
        out.title(f"[{item['severity'].upper()}] {item['title']}")
        out.info(item["detail"])
        if item.get("why_it_matters"):
            out.kv("why", item["why_it_matters"], width=10)
        if item.get("caveat"):
            out.warn(f"caveat: {item['caveat']}")
        if item.get("evidence"):
            for line in item["evidence"][:3]:
                out.info(f"      · {str(line)[:110]}")
        out.kv("cites", f"{len(item.get('artifact_ids', []))} artifact(s)",
               width=10)
        out.kv("confidence", item["confidence"], width=10)

    ents = result["entities"]
    if ents["total_entities"]:
        out.title("Entities extracted from content")
        out.table(["Kind", "Count"], list(ents["by_kind"].items()))
        high = ents.get("high_value") or []
        if high:
            out.title("High-value entities")
            out.table(["Type", "Value", "Seen", "Validated"],
                      [[h["label"], h["value"][:46], h["count"],
                        "yes" if h["validated"] else ""] for h in high[:20]])

    corr = result.get("correlation") or {}
    coloc = corr.get("colocation") or {}
    if corr.get("shared_party_count") or coloc.get("encounter_count"):
        out.title("Cross-exhibit correlation")
        out.kv("shared parties", corr.get("shared_party_count", 0))
        out.kv("shared media", corr.get("shared_media_count", 0))
        out.kv("shared locations", corr.get("shared_location_count", 0))
        if coloc.get("encounter_count"):
            out.kv("co-location encounters", coloc["encounter_count"])
        out.table(["Party", "Exhibits", "Artifacts", "Deleted on"],
                  [[p["best_label"], p["exhibit_count"],
                    sum(p["exhibits"].values()),
                    ", ".join(p["deleted_on"]) or "—"]
                   for p in corr.get("shared_parties", [])[:15]])

    comm = result.get("communities") or {}
    if comm.get("count"):
        out.title("Community structure")
        out.kv("communities", comm["count"])
        out.kv("modularity", comm["modularity"])
        out.info(comm["interpretation"])
    return 0


def cmd_thread(args, out: Out) -> int:
    """Read a conversation as a conversation."""
    from .analyze.conversations import build_conversations
    from .analyze.session import AnalysisSession
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        builder = build_conversations(session, owner_name=args.owner_name)
        threads = builder.build(min_turns=args.min_turns)
        summary = builder.summary(args.min_turns)

        if args.who:
            needle = args.who.lower()
            matched = [t for t in threads
                       if needle in t.label.lower() or needle in t.key]
            if not matched:
                out.err(f"no conversation matches {args.who!r}")
                return 1
            for thread in matched[:args.limit]:
                out.title(f"{thread.label} — {thread.app} "
                          f"({thread.size} turns, {thread.deleted} deleted)")
                data = thread.as_dict(include_turns=False)
                out.kv("span", f"{data['first_iso'][:19]} → "
                               f"{data['last_iso'][:19]}  "
                               f"({data['span_days']} days)")
                out.kv("in / out", f"{thread.incoming} / {thread.outgoing}")
                out.kv("reciprocity", thread.reciprocity)
                if thread.median_reply_seconds is not None:
                    out.kv("median reply", f"{thread.median_reply_seconds:.0f}s")
                if thread.longest_silence_hours:
                    out.kv("longest silence", f"{thread.longest_silence_hours}h")
                print()
                print(thread.transcript(limit=args.turns,
                                        owner_name=args.owner_name))
            return 0

        if args.json:
            print(json.dumps(summary, indent=2, default=str))
            return 0

        out.title(f"{summary['conversation_count']} conversation(s), "
                  f"{summary['relationship_count']} relationship(s)")
        out.kv("threads with deleted content",
               summary["threads_with_deleted_content"])
        out.kv("wholly deleted threads", summary["wholly_deleted_threads"])
        out.kv("multi-channel relationships",
               summary["multi_channel_relationships"])
        out.table(["Correspondent", "App", "Turns", "In/Out", "Deleted",
                   "Recip.", "Median reply"],
                  [[t.label, t.app, t.size, f"{t.incoming}/{t.outgoing}",
                    t.deleted, t.reciprocity,
                    f"{t.median_reply_seconds:.0f}s"
                    if t.median_reply_seconds is not None else "—"]
                   for t in threads[:args.limit]])
        out.info(summary["note"])
        out.ok(f"Read one with:  argus thread <container> --who \"<name>\"")
    return 0


def cmd_fuse(args, out: Out) -> int:
    """Attribute activity to a person rather than a device."""
    from .analyze.session import AnalysisSession
    from .intel.fusion import fuse_session
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        fuser = fuse_session(session, owner_name=args.owner_name)
        events = fuser.fuse()
        summary = fuser.summary(events)

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0

    out.title("Event fusion — attribution")
    out.kv("communications", summary["events"])
    out.kv("telemetry events", summary["telemetry_events"])
    out.kv("coverage", f"{summary['coverage']:.1%}")
    out.table(["Attribution", "Count", "Meaning"],
              [[k, v, summary["attribution_meanings"][k]]
               for k, v in summary["by_attribution"].items()])
    out.warn(summary["note"])

    wanted = args.attribution
    shown = [e for e in events if wanted in ("any", e.attribution)]
    shown.sort(key=lambda e: -e.strength)
    out.title(f"{len(shown)} event(s) — {wanted}")
    for event in shown[:args.limit]:
        data = event.as_dict()
        out.info(f"{data['timestamp_iso'][:19]}  "
                 f"[{data['attribution']}]  strength={data['strength']}  "
                 f"{data['summary'][:70]}")
        for c in data["corroboration"][:3]:
            out.info(f"      + {c['kind']:9s} {c['offset_seconds']:>8.1f}s  "
                     f"{c['detail'][:70]}")
    return 0


def cmd_media(args, out: Out) -> int:
    """Visual matching — the same picture across re-encoded files."""
    from .analyze.session import AnalysisSession
    from .parsers.media.perceptual import build_index
    with AnalysisSession([Path(c) for c in args.containers]) as session:
        index = build_index(session)
        summary = index.summary()

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0

    out.title("Perceptual image matching")
    for key in ("images_hashed", "images_skipped", "matches", "identical",
                "near_duplicates", "similar", "re_encoded_matches",
                "cluster_count", "cross_exhibit_clusters"):
        out.kv(key.replace("_", " "), summary[key])
    if summary["truncated"]:
        out.warn("comparison was truncated at the pair limit")

    out.title("Clusters of the same picture")
    for cluster in summary["clusters"][:args.limit]:
        out.info(f"size={cluster['size']}  distinct files="
                 f"{cluster['distinct_files']}  "
                 f"exhibits={', '.join(cluster['exhibits']) or '—'}")
        for member in cluster["members"][:6]:
            out.info(f"      {member['label'][:50]:52s} "
                     f"{member['sha256'][:12]}  {member['exhibit']}")
        out.info(f"      {cluster['note']}")
    if not summary["clusters"]:
        out.info("(no visually matching images)")
    return 0


def cmd_hashset(args, out: Out) -> int:
    """Screen evidence against known-good / known-bad hash sets."""
    from .analyze.session import AnalysisSession
    from .core.hashsets import HashSetRegistry, screen_session

    registry = HashSetRegistry()
    for spec in (args.good or []):
        hs = registry.load(spec, kind="known-good")
        out.ok(f"loaded known-good '{hs.name}' — {hs.size} entries "
               f"({', '.join(hs.algorithms)})")
    for spec in (args.bad or []):
        hs = registry.load(spec, kind="known-bad")
        out.ok(f"loaded known-bad '{hs.name}' — {hs.size} entries "
               f"({', '.join(hs.algorithms)})")
    if args.dir:
        for hs in registry.load_directory(args.dir):
            out.ok(f"loaded {hs.kind} '{hs.name}' — {hs.size} entries")
    if registry.empty:
        out.err("no hash sets loaded — supply --good, --bad or --dir")
        return 1

    with AnalysisSession([Path(c) for c in args.containers]) as session:
        result = screen_session(session, registry)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    summary = result["summary"]
    out.title("Hash-set screening")
    for key in ("sets_loaded", "total_entries", "screened", "known_good",
                "known_bad", "unknown", "suppression_rate"):
        out.kv(key.replace("_", " "), summary[key])
    out.info(summary["note"])

    if result["known_bad"]:
        out.title(f"{result['known_bad_count']} KNOWN-BAD match(es)")
        out.table(["File", "Set", "Algorithm", "Label", "Exhibit"],
                  [[b["filename"][:44], b["set_name"], b["algorithm"],
                    b["label"][:28], b["exhibit"]]
                   for b in result["known_bad"][:60]])
    else:
        out.ok("no known-bad matches")

    out.title("Set provenance")
    out.table(["Set", "Kind", "Entries", "Source", "Loaded"],
              [[p["name"], p["kind"], p["entries"],
                Path(p["source"]).name if p["source"] else "—",
                p["loaded_at"][:19]] for p in summary["provenance"]])
    out.warn("A known-bad hit is only as strong as the provenance of the set. "
             "Record where the set came from and when it was compiled.")
    return 0


def cmd_validate(args, out: Out) -> int:
    """Run the validation harness and report measured error rates."""
    from .validate.harness import run_validation
    report = run_validation(workdir=Path(args.workdir) if args.workdir else None,
                            seed=args.seed, keep_corpus=args.keep_corpus,
                            progress=None if args.json else out.ok)
    data = report.as_dict()

    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2, default=str),
                          encoding="utf-8")
    if args.json:
        print(json.dumps(data, indent=2, default=str))
        return 0 if data["summary"]["tests_failed"] == 0 else 1

    s = data["summary"]
    out.title("Validation summary")
    out.kv("tests run", s["tests_run"])
    out.kv("passed", s["tests_passed"])
    out.kv("failed", s["tests_failed"])
    out.kv("overall recall", s["overall_recall"])
    out.kv("overall precision", s["overall_precision"])
    out.kv("items expected", s["total_expected"])
    out.kv("items missed", s["total_missed"])
    out.kv("spurious items", s["total_spurious"])

    out.title("Measured error rates by capability")
    out.table(["Capability", "Tests", "Pass", "Recall", "Precision",
               "FN rate", "FP rate"],
              [[cap, m["tests"], m["passed"],
                "—" if m["recall"] is None else f"{m['recall']:.4f}",
                "—" if m["precision"] is None else f"{m['precision']:.4f}",
                "—" if m["false_negative_rate"] is None else f"{m['false_negative_rate']:.4f}",
                "—" if m["false_positive_rate"] is None else f"{m['false_positive_rate']:.4f}"]
               for cap, m in data["by_capability"].items()])

    failed = [r for r in data["results"] if not r["passed"]]
    if failed:
        out.title("Failures")
        for r in failed:
            out.err(f"{r['test_id']}: {r['description']}")
            if r["error"]:
                out.err(f"   {r['error']}")
            for item in r["missed_items"][:5]:
                out.err(f"   missed: {str(item)[:100]}")
    else:
        out.ok("All validation tests passed.")

    out.title("Stated limitations")
    for line in data["limitations"]:
        out.info(f"· {line}")
    if args.out:
        out.ok(f"Report written to {args.out}")
    return 0 if s["tests_failed"] == 0 else 1


def cmd_certificate(args, out: Out) -> int:
    """Issue or verify an evidence certificate."""
    from .validate.certificate import (ExaminerNote, build_certificate,
                                       generate_key, verify_certificate,
                                       write_certificate)
    if args.cert_action == "issue":
        validation = None
        if args.validation:
            validation = json.loads(Path(args.validation).read_text())
        notes = [ExaminerNote(author=args.examiner or "examiner", text=n)
                 for n in (args.note or [])]
        key = None
        if args.seal:
            key = generate_key()
        cert = build_certificate(
            [Path(c) for c in args.containers], examiner=args.examiner,
            organisation=args.organisation, reference=args.reference,
            notes=notes, validation=validation,
            peer_reviewer=args.peer_reviewer, key=key)
        path = write_certificate(cert, args.out)
        out.title("Evidence certificate issued")
        out.kv("File", path)
        out.kv("Containers", len(cert["containers"]))
        out.kv("All verified", cert["all_containers_verified"])
        out.kv("Digest", cert["certificate_sha256"][:48])
        out.kv("Validation attached", cert["validation"]["performed"])
        if key:
            key_path = Path(str(path) + ".key")
            key_path.write_text(key.hex(), encoding="utf-8")
            out.kv("Seal key", key_path)
            out.warn("Store the seal key separately from the certificate. "
                     "Without it the seal cannot be verified; with it, anyone "
                     "can re-seal an altered certificate.")
        if not cert["all_containers_verified"]:
            out.err("One or more containers FAILED verification — the "
                    "certificate records this.")
            return 4
        return 0

    if args.cert_action == "verify":
        key = None
        if args.key:
            key = bytes.fromhex(Path(args.key).read_text().strip())
        result = verify_certificate(args.certificate, key=key,
                                   recheck_evidence=not args.no_evidence)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0 if result["ok"] else 4
        out.title(f"Certificate verification — {Path(args.certificate).name}")
        out.kv("Issued", result["issued_at"])
        out.kv("Examiner", result["examiner"] or "—")
        out.kv("Tool at issue", result["tool_version_at_issue"])
        out.table(["Check", "Result"],
                  [[c["check"], "ok" if c["ok"] else
                    ("—" if c["ok"] is None else "FAILED")]
                   for c in result["checks"]])
        if result["ok"]:
            out.ok(result["conclusion"])
        else:
            out.err(result["conclusion"])
            for p in result["problems"]:
                out.err(p)
        return 0 if result["ok"] else 4
    return 1


def cmd_report(args, out: Out) -> int:
    from .analyze.session import AnalysisSession
    from .report.builder import ReportBuilder, ReportOptions

    opts = ReportOptions(
        title=args.title, scope=args.scope, query=args.query or "",
        formats=[f.strip() for f in args.formats.split(",")],
        include_deleted=not args.exclude_deleted,
        include_graph=not args.no_graph,
        include_timeline=not args.no_timeline,
        include_log=args.include_log, include_audit=args.include_audit,
        include_intelligence=not args.no_intelligence,
        owner_identifiers=[x.strip() for x in (args.owner or "").split(",")
                           if x.strip()],
        examiner=args.examiner, organisation=args.organisation,
        reference=args.reference, conclusion=args.conclusion or "",
        max_artifacts=args.max_artifacts)

    with AnalysisSession([Path(c) for c in args.containers],
                         deep_verify=not args.quick_verify) as session:
        if not session.integrity_ok:
            out.err("Container verification FAILED. The report will be "
                    "produced, but it will carry a prominent integrity "
                    "warning on its first page.")
        builder = ReportBuilder(session, opts)
        written = builder.write(args.out, args.basename)
    out.title("Report generated")
    out.kv("Artifacts", f"{builder.data['artifact_count']:,}")
    out.kv("Deleted included", f"{builder.data['deleted_count']:,}")
    for p in written:
        out.ok(f"{p}  ({_human(p.stat().st_size)})")
    return 0


def cmd_carve(args, out: Out) -> int:
    """Standalone deleted-record recovery from a single database file."""
    from .parsers.sqlite_reader import ForensicSQLite
    with ForensicSQLite(Path(args.database)) as db:
        out.title(f"SQLite forensic survey — {Path(args.database).name}")
        for k, v in db.header_report().items():
            out.kv(k.replace("_", " "), v)
        out.title("Integrity")
        for k, v in db.integrity().items():
            out.kv(k.replace("_", " "), v)

        tables = [args.table] if args.table else [
            t for t in db.schemas() if not t.startswith("sqlite_")]
        for table in tables:
            records = db.carve(table, min_confidence=args.confidence)
            if not records and not args.table:
                continue
            schema = db.schemas()[table]
            out.title(f"{table} — {len(records)} deleted record(s) recovered "
                      f"(live rows: {len(list(db.rows(table)))})")
            if args.json:
                print(json.dumps(
                    [r.as_row(schema.columns, schema.rowid_alias)
                     for r in records], indent=2, default=str))
                continue
            out.table(["Origin", "Conf", "Page", "RowID"] + schema.columns[:5],
                      [[r.origin, r.confidence, r.page, r.rowid]
                       + [str(v)[:38] for v in r.values[:5]]
                       for r in records], limit=args.limit)
    return 0


def cmd_mtp(args, out: Out) -> int:
    """Acquire from a handset that is browsable but not debuggable."""
    from .acquire import mtp

    if not mtp.available():
        out.err("MTP acquisition is implemented for Windows only.")
        out.info("On Linux or macOS, mount the handset with your desktop's "
                 "MTP support and import the mounted path instead.")
        return 1

    found = mtp.devices()
    if args.mtp_action == "list":
        out.title(f"Handsets mounted in the shell namespace ({len(found)})")
        if not found:
            out.warn("None. Set the USB mode to File transfer (MTP) on the "
                     "handset — it defaults to charge-only on most vendors.")
            return 1
        out.table(["Device"], [[d.name] for d in found])
        out.info("Acquire with:  argus mtp acquire \"<device>\" --out <dir>")
        return 0

    if args.mtp_action == "verify":
        from pathlib import Path
        p = Path(args.path)
        manifest = p if p.is_file() else p / "argus-mtp-manifest.json"
        if not manifest.is_file():
            # also try raw subdir
            alt = p / "raw" / "argus-mtp-manifest.json"
            if alt.is_file():
                manifest = alt
        if not manifest.is_file():
            out.err(f"No manifest found at {manifest}")
            return 1
        res = mtp.verify_manifest(manifest, root=manifest.parent)
        if getattr(args, "json", False):
            import json as _json
            print(_json.dumps(res, indent=2))
            return 0 if res.get("ok") else 4
        out.title(f"MTP Verify — {manifest.parent.name}")
        out.kv("unchanged", res["counts"]["unchanged"])
        out.kv("altered", res["counts"]["altered"])
        out.kv("missing", res["counts"]["missing"])
        out.kv("added", res["counts"]["added"])
        if res.get("ok"):
            out.ok("VERIFIED — all hashed files unchanged.")
            return 0
        for a in res.get("altered", [])[:8]:
            out.err(f"ALTERED: {a['path']}")
        for m in res.get("missing", [])[:8]:
            out.err(f"MISSING: {m}")
        for ad in res.get("added", [])[:8]:
            out.warn(f"ADDED (not in manifest): {ad}")
        return 4

    name = args.device or (found[0].name if found else "")
    if not name:
        out.err("No MTP handset is mounted.")
        return 1

    out.title(f"Acquiring {name}" + (" [GOD]" if getattr(args, "god", False) else ""))
    out.warn(mtp.METHOD_NOTE)
    god = bool(getattr(args, "god", False))
    # god forces full hashing + no turbo fast-lane, even if --turbo also passed
    result = mtp.acquire(name, args.out, progress=out.info,
                         hash_files=(not args.no_hash) or god,
                         resume=bool(getattr(args, "resume", False)),
                         turbo=(bool(getattr(args, "turbo", False)) and not god))

    out.title("Result")
    out.kv("files copied", f"{result.files_copied:,}")
    out.kv("bytes", f"{result.bytes_copied / (1024 ** 3):.2f} GB")
    out.kv("listed on device", f"{result.files_listed:,}")
    out.kv("did not arrive", len(result.missing))

    manifest = mtp.write_manifest(result, Path(args.out) / "argus-mtp-manifest.json")
    out.kv("manifest", str(manifest))

    for warning in result.warnings:
        out.warn(warning)
    if result.missing:
        out.title("Files listed but not copied")
        for entry in result.missing[:15]:
            out.info(f"  {entry['path']}")
        if len(result.missing) > 15:
            out.info(f"  … and {len(result.missing) - 15} more (see manifest)")
        return 2

    out.ok("Every listed file arrived. Import the folder to analyse it.")
    return 0


def cmd_watch(args, out: Out) -> int:
    """Watch USB for handset connect/disconnect transitions."""
    import time
    from .devices.watch import DeviceWatcher

    watcher = DeviceWatcher()
    watcher.reset()
    out.title(f"Watching USB for {args.seconds}s")
    out.info("Plug the handset in now. Choose File transfer / MTP if prompted.")
    deadline = time.time() + args.seconds
    while time.time() < deadline:
        result = watcher.poll()
        for ev in result.get("events", []):
            stamp = (ev.get("ts") or "")[11:19]
            line = f"{stamp}  {ev.get('message', '')}"
            kind = ev.get("kind", "")
            if kind in ("connected", "mtp"):
                out.ok(line)
            elif kind == "disconnected":
                out.warn(line)
            elif not out.quiet:
                print(f"  {line}")
        time.sleep(args.interval)
    out.ok(f"Watch ended — {result.get('count', 0)} device(s) connected")
    return 0


def cmd_bus(args, out: Out) -> int:
    """Everything attached, whether or not a forensic tool can talk to it."""
    from .devices.bus import scan_all

    report = scan_all()
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    out.title(f"USB ({report['usb_total']} device(s) enumerated)")
    if report["mobile_hardware"]:
        out.table(["VID:PID", "Vendor", "Description"],
                  [[f"{d['vendor_id']}:{d['product_id']}", d["vendor"],
                    d["description"][:44]]
                   for d in report["mobile_hardware"]])
    else:
        out.info("No handset-vendor hardware recognised on the bus.")

    if report["fastboot"]:
        out.title("Bootloader mode")
        for entry in report["fastboot"]:
            out.kv(entry["serial"], entry["note"][:90])

    if report["volumes"]:
        out.title("Mounted volumes")
        out.table(["Path", "Removable", "Looks like evidence", "Markers"],
                  [[v["path"], "yes" if v["removable"] else "no",
                    "yes" if v["looks_like_evidence"] else "no",
                    ", ".join(v["markers"][:4])]
                   for v in report["volumes"]])

    if report["notes"]:
        out.title("What this means")
        for note in report["notes"]:
            out.info(f"· {note}")
    return 0


def cmd_diagnose(args, out: Out) -> int:
    """Say why the handset is not being detected."""
    from .devices.diagnose import diagnose, vendor_guidance_for

    report = diagnose()
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
        return 0 if report.ready and not report.problems else 1

    out.title("Connection diagnosis")
    out.kv("adb", report.adb_path or "NOT FOUND")
    if report.adb_version:
        out.kv("version", report.adb_version)

    if report.devices:
        out.title(f"On the bus ({len(report.devices)})")
        out.table(["Serial", "State", "Model"],
                  [[d.serial, d.state, d.model or "—"] for d in report.devices])
    elif report.adb_available:
        out.title("On the bus")
        out.info("Nothing. adb is running and sees no handset at all.")

    if report.ready:
        out.title("Ready")
        for label in report.ready:
            out.ok(label)

    if report.problems:
        out.title("Problems")
        for problem in report.problems:
            out.err(problem["issue"])
            out.info(f"    → {problem['fix']}")

    guidance = list(report.vendor_guidance)
    if args.make and not guidance:
        # adb sees nothing, so there is no model string to key on — but the
        # examiner knows what they plugged in.
        guidance = vendor_guidance_for(args.make)
    if guidance:
        out.title("Vendor-specific")
        for note in guidance:
            out.info(f"  · {note}")

    if report.next_steps:
        out.title("Next")
        for step in report.next_steps:
            out.info(step)

    return 0 if report.ready and not report.problems else 1


def cmd_triage(args, out: Out) -> int:
    """Say what a container actually is before spending time on it."""
    from .acquire.msab import NATIVE_EXTENSIONS, resolve_case
    from .acquire.opaque import carve_container, triage

    source = Path(args.source)
    carve_source = source
    if source.is_file() and source.suffix.lower() in NATIVE_EXTENSIONS:
        resolved = resolve_case(source)
        if resolved.data_path and resolved.data_path != source:
            carve_source = resolved.data_path

    report = triage(source)
    if args.json and not args.carve:
        print(json.dumps(report.as_dict(), indent=2, default=str))
        return 0 if report.carvable else 1

    out.title(f"Triage — {source.name}")
    if carve_source != source:
        out.kv("data file", carve_source.name)
    out.kv("size", f"{report.size:,} bytes")
    out.kv("extension", report.extension or "—")
    out.kv("identified as", report.wrapper or "unrecognised")
    out.kv("entropy", f"{report.entropy:.2f} bits/byte")
    if report.zip_members:
        out.kv("archive members", report.zip_members)
        for name in report.zip_sample[:10]:
            out.info(f"    {name}")
    if report.embedded:
        out.kv("embedded files", ", ".join(
            f"{count}× {kind}" for kind, count in
            sorted(report.embedded.items(), key=lambda kv: -kv[1])))
    if report.wrapper_note:
        out.title("What this format is")
        out.info(report.wrapper_note)

    out.title("Assessment")
    out.info(report.recommendation)
    out.warn(report.caveat)

    if not args.carve:
        if report.carvable:
            out.ok("Run again with --carve --out <dir> to recover the files.")
        if (source.suffix.lower() in NATIVE_EXTENSIONS
                and report.carvable):
            out.ok(
                "Or import directly — ARGUS carves embedded files automatically:")
            out.info(
                f"  argus acquire <case> --exhibit <ID> --operator <name> "
                f'--method import --source "{source}"')
        return 0 if report.carvable else 1

    if not report.carvable:
        out.err("Nothing recoverable was identified; carving was not attempted.")
        return 1

    result = carve_container(carve_source, args.out)
    out.title("Recovery")
    out.kv("mode", result["mode"])
    out.kv("files recovered", result["files"])
    out.kv("written to", args.out)
    if carve_source != source:
        out.kv("carved from", str(carve_source))
    out.info(result["note"])
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_selfcheck(args, out: Out) -> int:
    """Verify the tool before it is used on evidence."""
    from .core.selfcheck import report

    data = report()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
        return 0 if data["verification"]["ok"] else 1

    v = data["verification"]
    out.title("ARGUS installation")
    out.kv("version", data["version"])
    out.kv("build", data["installation_id"][:32])
    out.kv("python", data["python"])
    out.kv("platform", data["platform"])

    out.title("Integrity")
    if v["ok"]:
        out.ok(f"{v['files_checked']} shipped files match the release manifest.")
    elif not v["manifest_present"]:
        out.warn("No release manifest — this build cannot be identified.")
        out.info(v["note"])
    else:
        out.err("Installation does not match its manifest.")
        for name in v["modified"][:20]:
            out.info(f"  modified : {name}")
        for name in v["missing"][:20]:
            out.info(f"  missing  : {name}")
        out.warn(v["note"])
    if v["unexpected"]:
        out.warn(f"{len(v['unexpected'])} file(s) not in the release manifest.")
        for name in v["unexpected"][:10]:
            out.info(f"  extra    : {name}")

    out.title("Optional features")
    out.table(["Feature", "Status", "If absent"],
              [[k, "available" + (f"  {d['detail']}" if d["detail"] else "")
                if d["available"] else "NOT AVAILABLE",
                "" if d["available"] else d["consequence_if_absent"]]
               for k, d in data["optional_features"].items()])

    out.info(data["note"])
    return 0 if v["ok"] else 1


def cmd_platforms(args, out: Out) -> int:
    """What ARGUS reads, per platform and per source format."""
    from .acquire import adapters
    from .devices.families import family_report
    from .devices.manual import DeviceManual
    from .parsers.platforms import platform_report

    report = platform_report()
    families = family_report()
    manual = DeviceManual()
    if args.json:
        print(json.dumps({"platforms": report,
                          "chipset_families": families,
                          "handsets": {
                              "count": len(manual),
                              "devices": [p.as_dict() for p in manual.profiles],
                          },
                          "adapters": [
                              {"name": a.name, "label": a.label,
                               "description": a.description,
                               "priority": a.priority}
                              for a in adapters.adapters()]},
                         indent=2, default=str))
        return 0

    out.title(f"Source formats ARGUS can import ({len(adapters.adapters())})")
    out.table(["Adapter", "Format", "Notes"],
              [[a.name, a.label, a.description]
               for a in adapters.adapters()])

    out.title(f"Platforms ({report['count']})")
    for profile in report["platforms"]:
        out.title(f"{profile['label']}")
        out.kv("decodes", ", ".join(profile["supported"]))
        if profile["not_supported"]:
            out.kv("not supported", ", ".join(profile["not_supported"]))
        if profile["note"]:
            out.info(profile["note"])

    out.title(f"Handsets in the device manual ({len(manual)})")
    by_make: Dict[str, int] = {}
    for entry in manual.profiles:
        by_make[entry.make] = by_make.get(entry.make, 0) + 1
    out.table(["Manufacturer", "Models"],
              [[make, str(count)]
               for make, count in sorted(by_make.items(),
                                         key=lambda kv: (-kv[1], kv[0]))])

    out.title(f"Chipset families used to assess uncatalogued devices "
              f"({families['count']})")
    out.table(["Family", "BootROM route", "Secure element"],
              [[f["name"], f["exploit"] or "—", f["secure_element"] or "—"]
               for f in families["families"]])
    out.info(families["note"])
    out.info(report["note"])
    return 0


def cmd_identify(args, out: Out) -> int:
    """Say what a source is before importing it."""
    from .acquire import adapters
    from .parsers.platforms import detect_platform

    described = adapters.describe(args.source)
    if args.json:
        print(json.dumps(described, indent=2, default=str))
        return 0 if described.get("ok") else 1
    if not described.get("ok"):
        out.err(described.get("reason", "unrecognised source"))
        out.info("Supported formats:")
        out.table(["Format", "Notes"],
                  [[a.label, a.description] for a in adapters.adapters()])
        return 1
    out.title("Source identified")
    out.kv("Path", described["path"])
    out.kv("Format", described["label"])
    out.kv("Adapter", described["adapter"])
    out.kv("Notes", described["description"])
    source = Path(args.source)
    if source.is_dir():
        name, confidence = detect_platform(source)
        out.kv("Platform", f"{name or 'not inferable'}"
                           + (f" ({confidence:.0%} confidence)" if name else ""))
    out.ok(f"Import with:  argus acquire <case> --exhibit <ID> "
           f"--operator <name> --method import --source \"{args.source}\"")
    return 0


def cmd_parsers(args, out: Out) -> int:
    from .parsers.registry import all_parsers, load_all
    load_all()
    out.title(f"{len(all_parsers())} registered parsers")
    out.table(["Priority", "Name", "Platform", "Patterns", "Description"],
              [[p.priority, p.name, p.platform or "any",
                ", ".join(p.patterns[:3]), p.description]
               for p in all_parsers()])
    return 0


# ------------------------------------------------------------------- parsing
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS Forensics — mobile device acquisition and analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  argus devices
  argus manual show "iPhone 12 mini"
  argus case new --dir ./cases --investigator "A. Sharma"
  argus exhibit add ./cases/CASE-20260729-101500 EXH-001 --make Apple --model "iPhone 12 mini" --isolation "Faraday pouch"
  argus acquire ./cases/CASE-... --exhibit EXH-001 --operator "A. Sharma" --method import --source ./ios_backup
  argus verify ./cases/CASE-.../exhibits/EXH-001/EXH-001_import_*.afc
  argus analyze ./cases/CASE-.../exhibits/EXH-001/*.afc
  argus query <container> 'category:Messages AND deleted:true'
  argus report <container> --formats html,pdf,xlsx --out ./reports
""")
    p.add_argument("--version", action="version", version=f"ARGUS {__version__}")
    p.add_argument("--no-colour", action="store_true", help="disable ANSI colour")
    p.add_argument("--quiet", "-q", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    # app — the one-click workbench
    ap = sub.add_parser("app", help="start the workbench application (GUI)")
    ap.add_argument("--workspace", default="~/ARGUS",
                    help="where cases and reports are kept")
    ap.add_argument("--port", type=int, default=8742)
    ap.add_argument("--no-browser", action="store_true")

    # devices
    sub.add_parser("devices", help="detect connected handsets (Step 7)")

    # manual
    m = sub.add_parser("manual", help="device capability manual (Steps 1-2)")
    ms = m.add_subparsers(dest="manual_action", required=True)
    msearch = ms.add_parser("search", help="search for a device model")
    msearch.add_argument("query")
    msearch.add_argument("--limit", type=int, default=10)
    mshow = ms.add_parser("show", help="capability overview for a device")
    mshow.add_argument("--chipset", default="",
                       help="SoC, used to infer a profile if the model is not "
                            "catalogued (e.g. 'MediaTek Helio G99')")
    mshow.add_argument("--os", default="",
                       help="OS family for inference (Android / iOS)")
    mshow.add_argument("--os-version", dest="os_version", default="",
                       help="OS release for inference (e.g. 13)")
    mshow.add_argument("query")
    ms.add_parser("list", help="list every device in the manual")

    # case
    c = sub.add_parser("case", help="case management (Steps 3-5)")
    cs = c.add_subparsers(dest="case_action", required=True)
    cnew = cs.add_parser("new", help="create a case")
    cnew.add_argument("--dir", default="./cases")
    cnew.add_argument("--id", default=None,
                      help="case ID (default: timestamp-based)")
    cnew.add_argument("--investigator", default="")
    cnew.add_argument("--organisation", default="")
    cnew.add_argument("--description", default="")
    cnew.add_argument("--password", default=None)
    clist = cs.add_parser("list", help="list cases")
    clist.add_argument("--dir", default="./cases")
    cshow = cs.add_parser("show", help="case overview")
    cshow.add_argument("path")
    cshow.add_argument("--password", default=None)
    cshow.add_argument("--json", action="store_true")

    # exhibit
    x = sub.add_parser("exhibit", help="register a seized item")
    xs = x.add_subparsers(dest="exhibit_action", required=True)
    xadd = xs.add_parser("add")
    xadd.add_argument("case")
    xadd.add_argument("exhibit_id")
    xadd.add_argument("--make", default="")
    xadd.add_argument("--model", default="")
    xadd.add_argument("--imei", default="")
    xadd.add_argument("--serial", default="")
    xadd.add_argument("--number", default="")
    xadd.add_argument("--description", default="")
    xadd.add_argument("--seized-at", default="")
    xadd.add_argument("--seized-by", default="")
    xadd.add_argument("--seized-from", default="")
    xadd.add_argument("--condition", default="")
    xadd.add_argument("--isolation", default="",
                      help="e.g. 'Faraday pouch' or 'Airplane mode'")
    xadd.add_argument("--password", default=None)

    # acquire
    a = sub.add_parser("acquire", help="run an extraction (Steps 8-13)")
    a.add_argument("case")
    a.add_argument("--exhibit", required=True, help="exhibit ID (Step 11)")
    a.add_argument("--operator", required=True, help="operator name (Step 11)")
    a.add_argument("--method", default="logical",
                   choices=["logical", "filesystem", "backup", "import",
                            "comprehensive", "mtp", "turbo", "physical",
                            "sim", "cloud"])
    a.add_argument("--span", default="all",
                   help="Step 9: all | 24h | 7d | 30d | 365d | FROM..TO")
    a.add_argument("--categories", default="all",
                   help="Step 10: comma-separated, or 'all'")
    a.add_argument("--device", default="",
                   help="model name to check against the device manual")
    a.add_argument("--lock-state", default="unlocked",
                   choices=["unlocked", "afu", "bfu", "locked"])
    a.add_argument("--serial", default=None)
    a.add_argument("--source", default=None,
                   help="for --method import/sim/cloud: dump, folder, or archive")
    a.add_argument("--physical-full", action="store_true",
                   help="physical: also image OS partitions (system/vendor/boot)")
    a.add_argument("--backup-password", default=None)
    a.add_argument("--owner", default="",
                   help="comma-separated identifiers belonging to the device owner")
    a.add_argument("--owner-name", default="Device owner")
    a.add_argument("--no-carve", action="store_true",
                   help="skip deleted-record recovery")
    a.add_argument("--carve-confidence", type=float, default=0.45)
    a.add_argument("--notes", default="")
    a.add_argument("--password", default=None, help="case password")
    a.add_argument("--resume", action="store_true",
                   help="resume the newest incomplete extraction for this exhibit")
    a.add_argument("--resume-container", default=None,
                   help="resume a specific incomplete .afc container path")
    a.add_argument("--turbo", action="store_true",
                   help="fastest extraction — parallel pulls, no carving, "
                        "no per-file verify during transfer")
    a.add_argument("--file-timeout", type=int, default=180,
                   help="per-file ADB pull timeout seconds (default 180; enhanced acquisition)")
    a.add_argument("--god", action="store_true",
                   help="god-level acquisition — maximum thoroughness + parallelism (9 passes, 300s timeout, all categories, verify)")

    ab = sub.add_parser("acquire-batch",
                        help="extract many connected handsets in one queue")
    ab.add_argument("case")
    ab.add_argument("--operator", required=True, help="operator name")
    ab.add_argument("--method", default="turbo",
                    choices=["logical", "filesystem", "backup",
                             "comprehensive", "mtp", "turbo", "physical"])
    ab.add_argument("--all-connected", action="store_true",
                    help="queue every ready handset currently attached")
    ab.add_argument("--plan", default=None,
                    help="JSON file listing devices to extract")
    ab.add_argument("--exhibit-prefix", default="EXH",
                    help="prefix for auto-registered exhibit IDs")
    ab.add_argument("--no-auto-exhibit", action="store_true",
                    help="do not register exhibits automatically")
    ab.add_argument("--stop-on-error", action="store_true",
                    help="halt the queue after the first failure")
    ab.add_argument("--span", default="all")
    ab.add_argument("--categories", default="all")
    ab.add_argument("--owner", default="")
    ab.add_argument("--owner-name", default="Device owner")
    ab.add_argument("--no-carve", action="store_true")
    ab.add_argument("--carve-confidence", type=float, default=0.45)
    ab.add_argument("--password", default=None, help="case password")
    ab.add_argument("--turbo", action="store_true",
                    help="fastest preset for every device in the queue")

    # verify
    v = sub.add_parser("verify", help="verify container integrity")
    v.add_argument("containers", nargs="+")
    v.add_argument("--quick", action="store_true",
                   help="skip re-hashing every blob")

    # analyze
    an = sub.add_parser("analyze", help="open the analysis UI (Steps 14-20)")
    an.add_argument("containers", nargs="+")
    an.add_argument("--host", default="127.0.0.1")
    an.add_argument("--port", type=int, default=8742)
    an.add_argument("--no-browser", action="store_true")
    an.add_argument("--deep-verify", action="store_true")
    an.add_argument("--owner-name", default="Device owner")
    an.add_argument("--tz", type=int, default=0,
                    help="display timezone offset in minutes")

    # query
    qp = sub.add_parser("query", help="run an AQL query headlessly")
    qp.add_argument("containers", nargs="+")
    qp.add_argument("--aql", "-a", default="",
                    help='AQL expression, e.g. \'category:Messages AND deleted:true\'')
    qp.add_argument("--limit", type=int, default=50)
    qp.add_argument("--order", default="timestamp DESC")
    qp.add_argument("--json", action="store_true")

    kw = sub.add_parser("keywords",
                        help="run a keyword list against sealed evidence")
    kw.add_argument("containers", nargs="+")
    kw.add_argument("--file", "-f", default="",
                    help="keyword file (one term per line)")
    kw.add_argument("--terms", "-t", default="",
                    help="comma-separated terms")
    kw.add_argument("--per-term", type=int, default=8)
    kw.add_argument("--json", action="store_true")

    # stats
    sp = sub.add_parser("stats", help="statistics and behavioural analysis")
    sp.add_argument("containers", nargs="+")
    sp.add_argument("--aql", default="")
    sp.add_argument("--json", action="store_true")

    # graph
    gp = sub.add_parser("graph", help="connection analysis (Steps 17, 19)")
    gp.add_argument("containers", nargs="+")
    gp.add_argument("--scope", default="all",
                    choices=["all", "calls", "messages"])
    gp.add_argument("--min-weight", type=int, default=1)
    gp.add_argument("--graphml", default=None, help="also write a GraphML file")
    gp.add_argument("--json", action="store_true")

    # report
    rp = sub.add_parser("report", help="generate the forensic report (Step 21)")
    rp.add_argument("containers", nargs="+")
    rp.add_argument("--out", default="./reports")
    rp.add_argument("--basename", default="forensic_report")
    rp.add_argument("--formats", default="html,pdf,xlsx",
                    help="html,pdf,xlsx,docx,xml,json,csv")
    rp.add_argument("--scope", default="all",
                    choices=["all", "filtered", "selected"])
    rp.add_argument("--query", default=None, help="AQL when --scope filtered")
    rp.add_argument("--title", default="Mobile Device Forensic Examination Report")
    rp.add_argument("--examiner", default="")
    rp.add_argument("--organisation", default="")
    rp.add_argument("--reference", default="")
    rp.add_argument("--conclusion", default=None)
    rp.add_argument("--exclude-deleted", action="store_true")
    rp.add_argument("--no-graph", action="store_true")
    rp.add_argument("--no-timeline", action="store_true")
    rp.add_argument("--include-log", action="store_true")
    rp.add_argument("--include-audit", action="store_true")
    rp.add_argument("--max-artifacts", type=int, default=20000)
    rp.add_argument("--quick-verify", action="store_true")
    rp.add_argument("--owner", default="",
                    help="comma-separated owner identifiers, for the findings")
    rp.add_argument("--no-intelligence", action="store_true",
                    help="omit the investigative findings section")

    # intel
    it = sub.add_parser("intel", help="investigative findings (lead sheet)")
    it.add_argument("containers", nargs="+")
    it.add_argument("--owner", default="",
                    help="comma-separated identifiers belonging to the owner")
    it.add_argument("--json", action="store_true")

    # thread
    th = sub.add_parser("thread", help="read conversations as conversations")
    th.add_argument("containers", nargs="+")
    th.add_argument("--who", default="", help="show the transcript for a name")
    th.add_argument("--min-turns", type=int, default=3)
    th.add_argument("--turns", type=int, default=60,
                    help="turns to print in a transcript")
    th.add_argument("--limit", type=int, default=30)
    th.add_argument("--owner-name", default="Device owner")
    th.add_argument("--json", action="store_true")

    # fuse
    fu = sub.add_parser("fuse",
                        help="attribute activity to a person, not just a device")
    fu.add_argument("containers", nargs="+")
    fu.add_argument("--attribution", default="attributed",
                    choices=["any", "attributed", "probable", "unattributed",
                             "unknown"])
    fu.add_argument("--limit", type=int, default=25)
    fu.add_argument("--owner-name", default="Device owner")
    fu.add_argument("--json", action="store_true")

    # media
    md = sub.add_parser("media",
                        help="visual matching — same picture, different files")
    md.add_argument("containers", nargs="+")
    md.add_argument("--limit", type=int, default=20)
    md.add_argument("--json", action="store_true")

    # hashset
    hs = sub.add_parser("hashset",
                        help="screen against known-good / known-bad hash sets")
    hs.add_argument("containers", nargs="+")
    hs.add_argument("--good", action="append",
                    help="known-good set (repeatable)")
    hs.add_argument("--bad", action="append",
                    help="known-bad set (repeatable)")
    hs.add_argument("--dir", default=None,
                    help="load every set in a directory")
    hs.add_argument("--json", action="store_true")

    # validate
    vl = sub.add_parser("validate",
                        help="run the validation harness; report error rates")
    vl.add_argument("--out", default=None, help="write the JSON report here")
    vl.add_argument("--workdir", default=None,
                    help="where to build the reference corpus")
    vl.add_argument("--seed", type=int, default=20260730)
    vl.add_argument("--keep-corpus", action="store_true")
    vl.add_argument("--json", action="store_true")

    # certificate
    ct = sub.add_parser("certificate", help="issue or verify an evidence certificate")
    cts = ct.add_subparsers(dest="cert_action", required=True)
    ci = cts.add_parser("issue")
    ci.add_argument("containers", nargs="+")
    ci.add_argument("--out", default="./certificate.json")
    ci.add_argument("--examiner", default="")
    ci.add_argument("--organisation", default="")
    ci.add_argument("--reference", default="")
    ci.add_argument("--peer-reviewer", default="")
    ci.add_argument("--validation", default=None,
                    help="attach a validation report JSON")
    ci.add_argument("--note", action="append",
                    help="examiner note (repeatable)")
    ci.add_argument("--seal", action="store_true",
                    help="seal with a generated HMAC key")
    cvf = cts.add_parser("verify")
    cvf.add_argument("certificate")
    cvf.add_argument("--key", default=None, help="path to the seal key file")
    cvf.add_argument("--no-evidence", action="store_true",
                     help="check the certificate only, not the evidence")
    cvf.add_argument("--json", action="store_true")

    # carve
    cv = sub.add_parser("carve",
                        help="recover deleted records from a SQLite database")
    cv.add_argument("database")
    cv.add_argument("--table", default=None)
    cv.add_argument("--confidence", type=float, default=0.45)
    cv.add_argument("--limit", type=int, default=40)
    cv.add_argument("--json", action="store_true")

    # platforms
    mt = sub.add_parser("mtp",
                        help="acquire from a handset mounted in file-transfer "
                             "mode (no USB debugging required)")
    mts = mt.add_subparsers(dest="mtp_action", required=True)
    mtl = mts.add_parser("list", help="list mounted handsets")
    mta = mts.add_parser("acquire", help="copy shared storage, with hashes")
    mta.add_argument("device", nargs="?", default="",
                     help="device name as shown by `argus mtp list`")
    mta.add_argument("--out", required=True, help="destination directory")
    mta.add_argument("--no-hash", action="store_true",
                     help="skip per-file hashing (faster, less defensible)")
    mta.add_argument("--turbo", action="store_true",
                     help="turbo MTP — disable hashing, faster settle (enhanced acquisition)")
    mta.add_argument("--resume", action="store_true",
                     help="resume interrupted MTP copy (uses listing cache)")
    mta.add_argument("--god", action="store_true",
                     help="god-level MTP — 3 Shell workers, 9-pass ADB overlay, 300s timeout, verify")
    mtv = mts.add_parser("verify", help="re-hash an MTP acquisition against its manifest")
    mtv.add_argument("path", help="destination dir or manifest path")
    mtv.add_argument("--json", action="store_true", help="output JSON")

    bs = sub.add_parser("bus",
                        help="list every attached device and volume the "
                             "operating system can see")
    bs.add_argument("--json", action="store_true")

    dg = sub.add_parser("diagnose",
                        help="say why a connected handset is not detected")
    dg.add_argument("--make", default="",
                    help="handset manufacturer, for skin-specific guidance "
                         "when adb sees nothing (e.g. oppo, xiaomi)")
    dg.add_argument("--json", action="store_true")

    wch = sub.add_parser("watch",
                         help="watch USB for handset connect/disconnect")
    wch.add_argument("--seconds", type=int, default=120,
                     help="how long to watch (default 120)")
    wch.add_argument("--interval", type=float, default=1.5,
                     help="poll interval in seconds")

    tr = sub.add_parser("triage",
                        help="say what a proprietary container actually is, "
                             "and recover what can be recovered from it")
    tr.add_argument("source")
    tr.add_argument("--carve", action="store_true",
                    help="extract the recognisable files")
    tr.add_argument("--out", default="./carved",
                    help="where to write recovered files")
    tr.add_argument("--json", action="store_true")

    sc = sub.add_parser("selfcheck",
                        help="verify this installation before using it on "
                             "evidence")
    sc.add_argument("--json", action="store_true")

    pf = sub.add_parser("platforms",
                        help="what ARGUS reads, per platform and source format")
    pf.add_argument("--json", action="store_true")

    # identify
    idp = sub.add_parser("identify",
                         help="say what a source is before importing it")
    idp.add_argument("source")
    idp.add_argument("--json", action="store_true")

    # god-tier single-command pipeline
    gd = sub.add_parser("god", help="god-tier end-to-end: acquire --god → verify → report → certificate")
    gd.add_argument("case", help="case folder (will be created if missing)")
    gd.add_argument("--exhibit", required=True, help="exhibit ID")
    gd.add_argument("--operator", required=True, help="operator name")
    gd.add_argument("--method", default="comprehensive", choices=["comprehensive","filesystem","logical","mtp","physical","god"])
    gd.add_argument("--device", default="", help="device model for manual check")
    gd.add_argument("--serial", default=None)
    gd.add_argument("--out", default="./reports", help="report output dir")
    gd.add_argument("--formats", default="html,pdf,xlsx,json", help="report formats")
    gd.add_argument("--quick", action="store_true", help="skip deep verify in pipeline")

    # parsers
    sub.add_parser("parsers", help="list registered artifact parsers")
    return p


def cmd_god(args, out: Out) -> int:
    """God-tier pipeline: acquire --god → verify → report → certificate (single command)."""
    from pathlib import Path as _P
    from .acquire.engine import AcquisitionEngine, AcquisitionPlan
    from .core.case import Case as _Case, Exhibit as _Exhibit
    from .core.container import EvidenceContainer as _EC
    from .report.builder import ReportBuilder as _RB, ReportOptions as _RO
    case_path = _P(args.case)
    # 1. case
    if not (case_path / "case.json").exists():
        out.title("GOD — creating case")
        case = _Case.create(str(case_path.parent), case_id=case_path.name, investigator=args.operator, organisation="", description="god-tier pipeline")
        case_path = case.root
    else:
        case = _Case.open(str(case_path))
    # 2. exhibit
    try:
        case.add_exhibit(_Exhibit(exhibit_id=args.exhibit, make=args.device.split()[0] if args.device else "", model=args.device))
        out.ok(f"Exhibit {args.exhibit} registered")
    except Exception:
        out.info(f"Exhibit {args.exhibit} already registered")
    # 3. acquire god
    out.title("GOD — acquiring (comprehensive, 9 passes, 300s, verify)")
    plan = AcquisitionPlan(method="comprehensive" if args.method=="god" else args.method, operator=args.operator, exhibit_id=args.exhibit, device_name=args.device, serial=args.serial, god=True, file_timeout=300, recover_deleted=True, verify_pulls=True)
    try:
        from .devices.detect import require_device as _req
        dev = _req(args.serial) if args.serial else None
    except Exception:
        dev = None
    engine = AcquisitionEngine(case)
    report = engine.run(plan, device=dev)
    out.kv("container", report.container)
    out.kv("artifacts", report.artifacts)
    out.kv("status", report.status)
    if report.status.startswith("Failed"):
        out.err("Acquisition failed — aborting god pipeline")
        return 1
    # 4. verify
    out.title("GOD — verifying manifest + seal")
    from .acquire.engine import verify_acquisition as _va
    vres = _va(report.container)
    out.kv("manifests", len(vres.get("manifests",{})))
    out.kv("ok", vres.get("ok"))
    # 5. report
    out.title("GOD — building report (all formats, graph, timeline, intel)")
    from .analyze.session import AnalysisSession as _AS
    with _AS([_P(report.container)]) as sess:
        builder = _RB(sess, _RO(formats=[f.strip() for f in args.formats.split(",") if f.strip()], include_deleted=True, include_graph=True, include_timeline=True, include_intelligence=True, examiner=args.operator))
        written = builder.write(_P(args.out), basename=f"god-{args.exhibit}")
    for p in written:
        out.ok(f"Report {p} ({_human(p.stat().st_size)})")
    out.title("GOD PIPELINE COMPLETE")
    out.ok(f"Case {case_path} Exhibit {args.exhibit} — container {report.container}")
    return 0


DISPATCH = {
    "devices": cmd_devices, "manual": cmd_manual, "case": cmd_case,
    "exhibit": cmd_exhibit, "acquire": cmd_acquire,
    "acquire-batch": cmd_acquire_batch, "verify": cmd_verify,
    "app": cmd_app, "intel": cmd_intel, "validate": cmd_validate,
    "certificate": cmd_certificate, "thread": cmd_thread, "fuse": cmd_fuse,
    "media": cmd_media, "hashset": cmd_hashset,
    "platforms": cmd_platforms, "identify": cmd_identify,
    "selfcheck": cmd_selfcheck, "triage": cmd_triage,
    "diagnose": cmd_diagnose, "bus": cmd_bus, "mtp": cmd_mtp, "watch": cmd_watch,
    "analyze": cmd_analyze, "query": cmd_query, "keywords": cmd_keywords,
    "stats": cmd_stats,
    "graph": cmd_graph, "report": cmd_report, "carve": cmd_carve,
    "parsers": cmd_parsers, "god": cmd_god,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out = Out(use_colour=not args.no_colour, quiet=args.quiet)
    try:
        return DISPATCH[args.command](args, out)
    except ArgusError as exc:
        out.err(str(exc))
        return getattr(exc, "exit_code", 1)
    except KeyboardInterrupt:
        out.warn("interrupted")
        return 130
    except BrokenPipeError:
        return 0


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


if __name__ == "__main__":
    sys.exit(main())
