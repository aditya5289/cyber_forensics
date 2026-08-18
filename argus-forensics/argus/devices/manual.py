"""Device Manual — capability matrix (lab manual §5.1, Steps 1–2).

Before touching a device an examiner must know *what is even possible* for
that model in its current lock state.  Getting this wrong is how devices get
bricked and evidence gets destroyed, which is exactly why the manual makes it
Step 1.

This module implements the ARGUS equivalent of the XRY Device Manual:

* a catalogue of device profiles (make/model/chipset/OS) with aliases,
* a capability matrix mapping **lock state → available extraction methods**,
* per-method risk, prerequisites, expected artifact yield and caveats,
* fuzzy search by model name, marketing name, chipset, or codename.

Lock states
-----------
``unlocked``   Device is unlocked and trusted by the workstation.
``afu``        After First Unlock — user has entered the passcode since boot,
               so file keys are in memory; agent/logical methods may work.
``bfu``        Before First Unlock — device booted and never unlocked. Most
               user data is still encrypted at rest; yield is minimal.
``locked``     Screen locked, state unknown.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.errors import DeviceNotSupportedError
from .families import family_report, infer

CATALOG_PATH = Path(__file__).with_name("catalog.json")

LOCK_STATES = ("unlocked", "afu", "bfu", "locked")

METHOD_INFO: Dict[str, Dict[str, Any]] = {
    "logical": {
        "label": "Logical (Full read)",
        "description": (
            "Requests data from the device operating system through its own "
            "APIs, within the permissions the OS grants. Fastest and least "
            "invasive; returns allocated records only."),
        "risk": "low",
        "yields_deleted": False,
        "typical_duration_min": 15,
    },
    "backup": {
        "label": "Backup extraction",
        "description": (
            "Triggers the vendor backup mechanism (Android adb backup / iOS "
            "iTunes backup) and parses the resulting archive. Coverage depends "
            "on which apps allow backup; iOS backups may be encrypted."),
        "risk": "low",
        "yields_deleted": False,
        "typical_duration_min": 30,
    },
    "filesystem": {
        "label": "File system extraction",
        "description": (
            "Copies the accessible file system, including application "
            "databases with their WAL and journal files. Enables recovery of "
            "deleted records still present in unallocated database pages."),
        "risk": "medium",
        "yields_deleted": True,
        "typical_duration_min": 60,
    },
    "comprehensive": {
        "label": "Comprehensive extraction",
        "description": (
            "God-level multi-pass acquisition: logical content-provider query, "
            "dynamic app database discovery, file-system pull with WAL sidecars, "
            "then dumpsys/backup-export fallbacks for Funtouch/Vivo handsets. "
            "Recommended default for maximum recoverable data on non-root Android."),
        "risk": "medium",
        "yields_deleted": True,
        "typical_duration_min": 90,
    },
    "mtp": {
        "label": "MTP (file transfer)",
        "description": (
            "Copies shared storage through the handset's media provider when "
            "USB debugging is unavailable. Every file is hashed; missing "
            "files are reported. Cannot reach /data/data."),
        "risk": "low",
        "yields_deleted": False,
        "typical_duration_min": 45,
    },
    "physical": {
        "label": "Physical extraction",
        "description": (
            "Bit-for-bit image of the flash storage. Highest yield including "
            "unallocated space, but requires an exploit or bootloader access "
            "and is unavailable on most modern encrypted devices."),
        "risk": "high",
        "yields_deleted": True,
        "typical_duration_min": 180,
    },
    "cloud": {
        "label": "Cloud extraction",
        "description": (
            "Retrieves data from the linked cloud account using tokens "
            "recovered from the device. Requires separate legal authority."),
        "risk": "medium",
        "yields_deleted": False,
        "typical_duration_min": 45,
    },
    "sim": {
        "label": "SIM card extraction",
        "description": "Reads ICCID, IMSI, SMS and ADN records from the SIM.",
        "risk": "low",
        "yields_deleted": True,
        "typical_duration_min": 5,
    },
    "screenshot": {
        "label": "Manual / photographic documentation",
        "description": (
            "Operator-driven capture of on-screen content. Always available "
            "and always admissible-by-documentation, but not a data extraction."),
        "risk": "low",
        "yields_deleted": False,
        "typical_duration_min": 30,
    },
}


@dataclass
class Capability:
    """One (lock state, method) cell of the matrix."""

    lock_state: str
    method: str
    supported: bool = True
    note: str = ""
    requires: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.update({k: v for k, v in METHOD_INFO.get(self.method, {}).items()})
        return d


@dataclass
class DeviceProfile:
    """A supported device."""

    make: str
    model: str
    aliases: List[str] = field(default_factory=list)
    os_family: str = ""
    os_versions: str = ""
    chipset: str = ""
    codename: str = ""
    released: str = ""
    connector: str = ""
    capabilities: List[Capability] = field(default_factory=list)
    notes: str = ""

    @property
    def name(self) -> str:
        return f"{self.make} {self.model}".strip()

    def methods_for(self, lock_state: str) -> List[Capability]:
        ls = lock_state.lower()
        return [c for c in self.capabilities
                if c.lock_state == ls and c.supported]

    def best_method(self, lock_state: str) -> Optional[str]:
        """Highest-yield supported method, preferring lower risk on ties."""
        order = ["comprehensive", "filesystem", "logical", "mtp", "backup",
                 "physical", "sim", "screenshot"]
        avail = {c.method for c in self.methods_for(lock_state)}
        for m in order:
            if m in avail:
                return m
        return None

    def matrix(self) -> Dict[str, List[Dict[str, Any]]]:
        return {ls: [c.as_dict() for c in self.methods_for(ls)]
                for ls in LOCK_STATES}

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["name"] = self.name
        d["matrix"] = self.matrix()
        return d

    def search_blob(self) -> str:
        return " ".join([self.make, self.model, self.chipset, self.codename,
                         self.os_family, *self.aliases]).lower()


def _cap(states_methods: Dict[str, List[str]],
         notes: Optional[Dict[str, str]] = None) -> List[Capability]:
    notes = notes or {}
    out: List[Capability] = []
    for state, methods in states_methods.items():
        for m in methods:
            out.append(Capability(lock_state=state, method=m,
                                  note=notes.get(f"{state}:{m}", "")))
    return out


# --------------------------------------------------------------------------
# Built-in catalogue. Deliberately small but *honest*: each entry encodes the
# real-world constraint that matters (e.g. BFU on a modern iPhone yields almost
# nothing). Extend via catalog.json or `DeviceManual.add_profile`.
# --------------------------------------------------------------------------
_IOS_MODERN = _cap(
    {
        "unlocked": ["logical", "backup", "filesystem", "cloud", "sim", "screenshot"],
        "afu": ["logical", "backup", "sim", "screenshot"],
        "bfu": ["backup", "sim", "screenshot"],
        "locked": ["backup", "sim", "screenshot"],
    },
    {
        "unlocked:filesystem": "Requires an unlocked, trusted device and a valid agent licence.",
        "afu:logical": "Only if the workstation already holds a valid pairing record (lockdown certificate).",
        "afu:backup": "Keep the handset unlocked and trusted. Encrypted backups need the password.",
        "locked:backup": "Unlock the iPhone and tap Trust, then start the backup.",
        "bfu:backup": "BFU user data stays encrypted; a backup still requires unlock.",
        "bfu:sim": "Handset user data remains encrypted; only SIM-resident data is reachable.",
    },
)

_ANDROID_MODERN = _cap(
    {
        "unlocked": ["comprehensive", "logical", "backup", "filesystem", "mtp",
                     "cloud", "sim", "screenshot"],
        "afu": ["comprehensive", "logical", "backup", "mtp", "sim", "screenshot"],
        "bfu": ["sim", "screenshot"],
        "locked": ["sim", "screenshot"],
    },
    {
        "unlocked:logical": "Requires USB debugging enabled and the workstation RSA key authorised.",
        "unlocked:comprehensive": "Best yield on non-root Android — logical + filesystem + dumpsys/Vivo exports.",
        "unlocked:mtp": "Windows only. Copies shared storage when USB debugging is off or as a media supplement.",
        "unlocked:backup": "adb backup is deprecated from Android 12; many apps set allowBackup=false.",
        "unlocked:filesystem": "Full /data access requires root or a vendor service exploit.",
        "afu:logical": "Limited to what a non-root ADB shell can read.",
        "afu:mtp": "Shared storage copy — does not reach /data/data.",
    },
)

_ANDROID_LEGACY = _cap(
    {
        "unlocked": ["logical", "backup", "filesystem", "physical", "cloud", "sim", "screenshot"],
        "afu": ["logical", "backup", "physical", "sim", "screenshot"],
        "bfu": ["physical", "sim", "screenshot"],
        "locked": ["physical", "sim", "screenshot"],
    },
    {
        "bfu:physical": "Unencrypted or FDE-default devices may yield a full image via bootloader.",
        "locked:physical": "Method depends on an unpatched bootloader or test-point access.",
    },
)

BUILTIN_PROFILES: List[DeviceProfile] = [
    DeviceProfile(
        make="Apple", model="iPhone 12 mini",
        aliases=["iPhone13,1", "A2176", "iphone12mini"],
        os_family="iOS", os_versions="14.0 – 18.x", chipset="Apple A14 Bionic",
        codename="D52gAP", released="2020-11", connector="Lightning",
        capabilities=_IOS_MODERN,
        notes=("Reference device for this exercise. Secure Enclave gates all "
               "user data at rest; BFU acquisition returns effectively no user "
               "content."),
    ),
    DeviceProfile(
        make="Apple", model="iPhone 12",
        aliases=["iPhone13,2", "A2172"], os_family="iOS",
        os_versions="14.0 – 18.x", chipset="Apple A14 Bionic",
        codename="D53gAP", released="2020-10", connector="Lightning",
        capabilities=_IOS_MODERN,
    ),
    DeviceProfile(
        make="Apple", model="iPhone 14 Pro",
        aliases=["iPhone15,2", "A2650"], os_family="iOS",
        os_versions="16.0 – 18.x", chipset="Apple A16 Bionic",
        released="2022-09", connector="Lightning",
        capabilities=_IOS_MODERN,
    ),
    DeviceProfile(
        make="Apple", model="iPhone 15",
        aliases=["iPhone15,4", "A3090"], os_family="iOS",
        os_versions="17.0 – 18.x", chipset="Apple A16 Bionic",
        released="2023-09", connector="USB-C",
        capabilities=_IOS_MODERN,
    ),
    DeviceProfile(
        make="Samsung", model="Galaxy S21 5G",
        aliases=["SM-G991B", "o1s"], os_family="Android",
        os_versions="11 – 14", chipset="Exynos 2100 / Snapdragon 888",
        codename="o1s", released="2021-01", connector="USB-C",
        capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="Samsung", model="Galaxy A52",
        aliases=["SM-A525F", "a52q"], os_family="Android",
        os_versions="11 – 13", chipset="Snapdragon 720G",
        released="2021-03", connector="USB-C",
        capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="Samsung", model="Galaxy J7",
        aliases=["SM-J700F", "j7elte"], os_family="Android",
        os_versions="5.1 – 8.1", chipset="Exynos 7580",
        released="2015-06", connector="Micro-USB",
        capabilities=_ANDROID_LEGACY,
        notes="Pre-FBE device; physical extraction commonly viable.",
    ),
    DeviceProfile(
        make="Xiaomi", model="Redmi Note 10",
        aliases=["M2101K7AI", "mojito"], os_family="Android",
        os_versions="11 – 13", chipset="Snapdragon 678",
        released="2021-03", connector="USB-C",
        capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="OnePlus", model="Nord CE 2",
        aliases=["IV2201"], os_family="Android", os_versions="11 – 13",
        chipset="MediaTek Dimensity 900", released="2022-02", connector="USB-C",
        capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="Google", model="Pixel 6",
        aliases=["GB7N6", "oriole"], os_family="Android", os_versions="12 – 15",
        chipset="Google Tensor", codename="oriole", released="2021-10",
        connector="USB-C", capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="Motorola", model="Moto G54",
        aliases=["XT2343"], os_family="Android", os_versions="13 – 14",
        chipset="MediaTek Dimensity 7020", released="2023-09", connector="USB-C",
        capabilities=_ANDROID_MODERN,
    ),
    DeviceProfile(
        make="vivo", model="Y02",
        aliases=["V2217", "V2217i", "vivo Y02", "BBK V2217"],
        os_family="Android", os_versions="12 Go", chipset="MediaTek Helio P35",
        codename="V2217", released="2022-12", connector="Micro-USB",
        capabilities=_ANDROID_MODERN,
        notes=("Budget Funtouch handset. VID 2D95 in MTP-only mode. Enable "
               "Developer options (tap Software version 7×), USB debugging "
               "and USB debugging (Security settings) for comprehensive ADB. "
               "Contacts/calls providers often empty — dumpsys and .vivobackup "
               "exports are critical."),
    ),
    DeviceProfile(
        make="Nokia", model="105 (2019)",
        aliases=["TA-1174"], os_family="Series 30+", os_versions="n/a",
        chipset="MediaTek MT6261", released="2019-07", connector="Micro-USB",
        capabilities=_cap({
            "unlocked": ["logical", "sim", "screenshot"],
            "locked": ["sim", "screenshot"],
        }, {"unlocked:logical": "Feature phone: contacts, SMS and call log only."}),
        notes="Feature phone. No file system or application data.",
    ),
]


class DeviceManual:
    """Searchable device capability database (manual Steps 1–2)."""

    def __init__(self, profiles: Optional[List[DeviceProfile]] = None):
        self.profiles: List[DeviceProfile] = list(profiles or BUILTIN_PROFILES)
        if CATALOG_PATH.exists():
            try:
                self.load_catalog(CATALOG_PATH)
            except Exception:                                 # pragma: no cover
                pass

    # ------------------------------------------------------------------ load
    def load_catalog(self, path: Path | str) -> int:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        added = 0
        for entry in data.get("devices", []):
            caps = [Capability(**c) for c in entry.pop("capabilities", [])]
            self.add_profile(DeviceProfile(capabilities=caps, **entry))
            added += 1
        return added

    def add_profile(self, profile: DeviceProfile) -> None:
        key = profile.name.lower()
        self.profiles = [p for p in self.profiles if p.name.lower() != key]
        self.profiles.append(profile)

    # ---------------------------------------------------------------- search
    # Score floors. Browsing is forgiving so an examiner can find a device from
    # a partial name; *selecting* one is not, because a fuzzy near-miss that
    # silently resolves to the wrong handset is how the capability matrix ends
    # up authorising a method the real device does not support.
    BROWSE_THRESHOLD = 20.0
    SELECT_THRESHOLD = 45.0

    def search(self, query: str, limit: int = 10,
               min_score: Optional[float] = None
               ) -> List[DeviceProfile]:
        """Step 1: search the manual for the target device model."""
        return [p for _, p in self.scored_search(query, limit, min_score)]

    def scored_search(self, query: str, limit: int = 10,
                      min_score: Optional[float] = None
                      ) -> List[tuple[float, DeviceProfile]]:
        q = re.sub(r"\s+", " ", (query or "").strip().lower())
        floor = self.BROWSE_THRESHOLD if min_score is None else min_score
        if not q:
            return [(0.0, p) for p in
                    sorted(self.profiles, key=lambda x: x.name)[:limit]]

        scored: List[tuple[float, DeviceProfile]] = []
        tokens = [t for t in q.split() if t]
        for p in self.profiles:
            blob = p.search_blob()
            score = 0.0
            if q == p.name.lower():
                score += 100
            if q in blob:
                score += 40
            matched = sum(1 for t in tokens if t in blob)
            score += 10 * matched
            # Fuzzy similarity is a tie-breaker, not evidence of a match: cap
            # its contribution below the selection threshold so it can never
            # promote an unrelated device on its own.
            score += 18 * difflib.SequenceMatcher(None, q, p.name.lower()).ratio()
            for alias in p.aliases:
                if q == alias.lower():
                    score += 90
                elif q in alias.lower():
                    score += 25
            if tokens and matched == 0 and q not in blob:
                continue          # nothing in the query appears in this profile
            if score >= floor:
                scored.append((score, p))
        scored.sort(key=lambda x: (-x[0], x[1].name))
        return scored[:limit]

    def get(self, name: str) -> DeviceProfile:
        """Step 2: select the exact model. Raises if genuinely unknown."""
        hits = self.scored_search(name, limit=1,
                                  min_score=self.SELECT_THRESHOLD)
        if not hits:
            near = self.search(name, limit=3)
            suggestion = (f" Closest entries: "
                          f"{', '.join(p.name for p in near)}." if near else "")
            raise DeviceNotSupportedError(
                f"'{name}' is not in the device manual.{suggestion} Do not "
                f"attempt extraction on an unverified device — see manual §7, "
                f"precaution 1.")
        return hits[0][1]

    def profile_or_inference(self, name: str, chipset: str = "",
                             os_family: str = "", os_version: str = ""
                             ) -> Dict[str, Any]:
        """Resolve a device, falling back to chipset-family inference.

        No catalogue covers every handset, and a seized phone is often a model
        nobody in the lab has met. Refusing outright is not caution, it is a
        dead end — what actually governs acquisition is the chipset, the OS
        release and the encryption scheme, none of which require this exact
        model to have been tested.

        So when the catalogue misses, this derives a profile from those
        properties and returns it clearly marked ``inferred``, with the
        reasoning attached and a confidence that never reaches a catalogued
        entry's. The examiner gets a defensible starting point and can see
        precisely how much it is worth.
        """
        try:
            profile = self.get(name)
        except DeviceNotSupportedError:
            pass
        else:
            return {"matched": True, "inferred": False, "confidence": 1.0,
                    "device": profile.as_dict(),
                    "source": "device manual (catalogued entry)"}

        if not (chipset or os_family):
            raise DeviceNotSupportedError(
                f"'{name}' is not in the device manual and no chipset or OS "
                f"was supplied, so no profile can be derived. Read the chipset "
                f"from the device (Settings > About, or the regulatory label) "
                f"and pass it in, or document the device manually per manual "
                f"§7, precaution 1.")

        inference = infer(os_family=os_family, chipset=chipset,
                          os_version=os_version, model=name)
        near = self.search(name, limit=3)
        return {
            "matched": False,
            "inferred": True,
            "confidence": inference.confidence,
            "query": name,
            "inference": inference.as_dict(),
            "similar_catalogued": [p.name for p in near],
            "source": "derived from chipset family and OS release",
        }

    def overview(self, name: str) -> Dict[str, Any]:
        """Device Overview panel: OS, chipset, capability matrix (Fig. 5.1)."""
        p = self.get(name)
        rows = []
        for ls in LOCK_STATES:
            caps = p.methods_for(ls)
            rows.append({
                "lock_state": ls,
                "label": {
                    "unlocked": "Unlocked",
                    "afu": "Locked (After First Unlock)",
                    "bfu": "Locked (Before First Unlock)",
                    "locked": "Locked (state unknown)",
                }[ls],
                "methods": [c.as_dict() for c in caps],
                "recommended": p.best_method(ls),
            })
        return {
            "device": p.as_dict(),
            "capability_overview": rows,
            "warning": (
                "Verify this information against the physical device before "
                "connecting it. Attempting an unsupported method risks data "
                "loss or device damage."),
        }

    def assert_supported(self, name: str, lock_state: str, method: str) -> Capability:
        """Gate an acquisition. This is the check that prevents Step 8 mistakes."""
        p = self.get(name)
        ls = (lock_state or "unlocked").lower()
        if ls not in LOCK_STATES:
            raise DeviceNotSupportedError(
                f"unknown lock state {lock_state!r}; expected one of {LOCK_STATES}")
        wanted = method
        if (p.os_family or "").lower().startswith("ios"):
            wanted = {
                "ios_backup": "backup",
                "turbo": "backup",
                "comprehensive": "backup",
                "logical": "backup",
                "filesystem": "backup",
                "mtp": "backup",
            }.get(method, method)
        for c in p.methods_for(ls):
            if c.method == wanted:
                return c
        available = sorted({c.method for c in p.methods_for(ls)})
        raise DeviceNotSupportedError(
            f"{p.name} in state '{ls}' does not support '{method}'. "
            f"Available: {', '.join(available) or 'none'}.")

    def __len__(self) -> int:
        return len(self.profiles)
