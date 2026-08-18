"""Capability inference for handsets that are not in the catalogue.

No catalogue is ever complete. New models ship weekly, regional variants carry
different chipsets under the same marketing name, and a seized phone is often a
brand nobody in the lab has met. A tool that answers "unsupported device" in
that situation is not being careful, it is being useless: what actually governs
extraction is the chipset, the OS release and the encryption scheme, not the
name printed on the back.

So this module answers the question the examiner is really asking — *what can I
attempt on this thing?* — from the properties that determine the answer. What it
must never do is present that inference as though it were a tested result. Every
profile produced here is flagged ``inferred`` with the reasoning attached, and
its confidence is capped below that of a catalogue entry, so an examiner can see
exactly how much weight the answer carries.

The determining factors, in order:

* **Encryption scheme.** Android moved from no encryption, to full-disk (FDE,
  Android 5–9), to file-based (FBE, Android 10+). FBE is what makes BFU
  acquisition barren, because file keys stay wrapped until first unlock.
* **Bootloader exploitability.** Some SoC families have publicly documented
  BootROM entry points that are unpatchable in silicon — MediaTek's "Kamakiri"
  BootROM download mode, Qualcomm's EDL with a leaked signed loader, Samsung
  Exynos in some generations. These permit physical acquisition regardless of
  lock state, which nothing else does.
* **Secure element.** An Apple Secure Enclave, a Titan M, or a Knox-backed
  Samsung device gates keys in hardware; brute force is rate-limited in silicon.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────── chipset families
@dataclass
class ChipsetFamily:
    """One SoC family and what it implies for acquisition."""

    name: str
    vendor: str
    patterns: List[str]
    bootrom_exploit: bool = False
    exploit_name: str = ""
    secure_element: str = ""
    note: str = ""

    def matches(self, text: str) -> bool:
        return any(re.search(p, text, re.I) for p in self.patterns)


CHIPSET_FAMILIES: List[ChipsetFamily] = [
    ChipsetFamily(
        "Apple A-series (Secure Enclave)", "Apple",
        [r"\bapple a\d", r"\bA\d{1,2} bionic", r"\bapple s\d"],
        bootrom_exploit=False,
        secure_element="Secure Enclave Processor",
        note=("A12 and later have no known BootROM exploit. A11 and earlier are "
              "checkm8-vulnerable, which permits a BFU physical image, but the "
              "user data on it stays encrypted without the passcode."),
    ),
    ChipsetFamily(
        "Apple A-series (checkm8-vulnerable)", "Apple",
        [r"\bapple a[5-9]\b", r"\bapple a10", r"\bapple a11"],
        bootrom_exploit=True, exploit_name="checkm8",
        secure_element="Secure Enclave (A7+)",
        note=("BootROM flaw is unpatchable. Yields a physical image at any lock "
              "state; decryption still requires the passcode on A7 and later."),
    ),
    ChipsetFamily(
        "MediaTek (BootROM download mode)", "MediaTek",
        [r"\bmt6\d{3}", r"\bmt8\d{3}", r"\bmediatek", r"\bdimensity",
         r"\bhelio\b"],
        bootrom_exploit=True, exploit_name="BootROM DA (Kamakiri-class)",
        note=("Many MediaTek SoCs expose a BootROM download agent over USB that "
              "predates any user authentication. Where the device is unencrypted "
              "or FDE with a known key this gives a full physical image."),
    ),
    ChipsetFamily(
        "Qualcomm Snapdragon", "Qualcomm",
        [r"\bsnapdragon", r"\bsdm?\d{3}", r"\bqualcomm", r"\bmsm\d+",
         r"\bsm\d{4}"],
        bootrom_exploit=False,
        note=("Emergency Download Mode (EDL, 9008) can image the flash, but "
              "requires a signed programmer for that specific OEM. Where no "
              "signed loader is held, treat physical as unavailable."),
    ),
    ChipsetFamily(
        "Samsung Exynos", "Samsung",
        [r"\bexynos", r"\bs5e\d+"],
        bootrom_exploit=False,
        secure_element="Knox / TrustZone",
        note=("Knox trip is irreversible and destroys the keystore. Bootloader "
              "unlocking on an Exynos device wipes user data by design, so it "
              "is not an acquisition route."),
    ),
    ChipsetFamily(
        "Google Tensor", "Google",
        [r"\btensor\b", r"\bgs\d{3}"],
        secure_element="Titan M2",
        note="Titan M2 rate-limits passcode attempts in hardware.",
    ),
    ChipsetFamily(
        "HiSilicon Kirin", "HiSilicon",
        [r"\bkirin", r"\bhi\d{4}"],
        note=("Huawei/Honor devices on Kirin use a proprietary partition layout. "
              "Post-2019 models have no public acquisition route beyond logical."),
    ),
    ChipsetFamily(
        "Unisoc / Spreadtrum", "Unisoc",
        [r"\bunisoc", r"\bspreadtrum", r"\bsc\d{4}", r"\bt\d{3}\b", r"\btiger\b"],
        bootrom_exploit=True, exploit_name="SPRD boot ROM diagnostic mode",
        note=("Common in low-cost handsets. Diagnostic mode frequently permits a "
              "full read; encryption is often absent or default-keyed."),
    ),
]


# ───────────────────────────────────────────────────────── encryption by release
def android_encryption(version: float) -> Tuple[str, str]:
    """Return ``(scheme, consequence)`` for an Android release."""
    if version <= 0:
        return "unknown", "Encryption scheme could not be determined."
    if version < 5:
        return "none", ("Storage is typically unencrypted. A physical image, if "
                        "obtainable, is directly readable.")
    if version < 10:
        return "FDE", ("Full-disk encryption with a default password unless the "
                       "user set one. A physical image is often decryptable.")
    return "FBE", ("File-based encryption. Credential-encrypted files stay "
                   "wrapped until first unlock, so a BFU image yields little "
                   "user content even when the image itself succeeds.")


def ios_encryption(version: float) -> Tuple[str, str]:
    if version <= 0:
        return "unknown", "Encryption scheme could not be determined."
    return "Data Protection", (
        "Per-file keys wrapped by the Secure Enclave. Class A/B files are "
        "unreadable before first unlock regardless of acquisition method.")


# ─────────────────────────────────────────────────────────────────── inference
@dataclass
class Inference:
    """A capability profile derived rather than catalogued."""

    os_family: str
    chipset: str
    family: Optional[ChipsetFamily] = None
    encryption: str = ""
    methods: Dict[str, List[str]] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)
    confidence: float = 0.0
    inferred: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "os_family": self.os_family,
            "chipset": self.chipset,
            "chipset_family": self.family.name if self.family else "",
            "encryption": self.encryption,
            "methods": self.methods,
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 2),
            "inferred": True,
            "caveat": (
                "This profile was inferred from chipset and OS version, not "
                "measured on this model. Treat the method list as candidates to "
                "attempt in a documented order, not as a guarantee. Verify on a "
                "test device of the same model before relying on it in a case."),
        }


def identify_chipset(text: str) -> Optional[ChipsetFamily]:
    """Match a chipset string to a family. Apple ordering is deliberate.

    The checkm8 entry is checked first because its pattern is the narrower one;
    a generic "Apple A-series" match would otherwise swallow A9 and A10 devices
    and hide the fact that they are exploitable.
    """
    if not text:
        return None
    ordered = sorted(CHIPSET_FAMILIES,
                     key=lambda f: 0 if f.bootrom_exploit else 1)
    for family in ordered:
        if family.matches(text):
            return family
    return None


def _parse_version(text: str) -> float:
    match = re.search(r"(\d+(?:\.\d+)?)", str(text or ""))
    return float(match.group(1)) if match else 0.0


def infer(os_family: str = "", chipset: str = "", os_version: str = "",
          model: str = "") -> Inference:
    """Derive an acquisition profile for a device not in the catalogue."""
    blob = f"{chipset} {model}".strip()
    family = identify_chipset(blob)
    version = _parse_version(os_version)
    os_name = (os_family or "").strip()
    if not os_name:
        if family and family.vendor == "Apple":
            os_name = "iOS"
        elif family:
            os_name = "Android"

    reasoning: List[str] = []
    confidence = 0.30

    if family:
        confidence += 0.25
        reasoning.append(f"Chipset resolves to {family.name}.")
        if family.note:
            reasoning.append(family.note)
    else:
        reasoning.append(
            "Chipset was not recognised, so acquisition routes specific to the "
            "SoC cannot be assessed. Only OS-level methods are listed.")

    if os_name.lower().startswith("ios") or os_name.lower() == "ipados":
        scheme, consequence = ios_encryption(version or 1)
    elif os_name.lower() == "android":
        scheme, consequence = android_encryption(version)
    else:
        scheme, consequence = "unknown", (
            "Operating system not identified; capabilities cannot be derived "
            "from the release.")
    reasoning.append(consequence)
    if version:
        confidence += 0.20
        reasoning.append(f"OS release parsed as {version:g}.")
    else:
        reasoning.append(
            "OS version unknown. Encryption scheme is the dominant factor in "
            "what BFU acquisition returns, so this is a material gap.")

    # Baseline: what the OS itself offers.
    methods: Dict[str, List[str]] = {
        "unlocked": ["logical", "backup", "sim", "screenshot"],
        "afu": ["logical", "backup", "sim", "screenshot"],
        "bfu": ["sim", "screenshot"],
        "locked": ["backup", "sim", "screenshot"],
    }
    if os_name.lower() == "android":
        methods["unlocked"].insert(2, "filesystem")
        methods["unlocked"].append("cloud")
        methods["afu"].insert(1, "backup")
    elif os_name.lower().startswith("i"):
        methods["unlocked"].insert(2, "filesystem")
        methods["unlocked"].append("cloud")
        methods["afu"].insert(1, "backup")

    # A BootROM-level entry point outranks the lock state entirely.
    if family and family.bootrom_exploit:
        confidence += 0.10
        for state in methods:
            methods[state] = ["physical"] + methods[state]
        reasoning.append(
            f"{family.exploit_name} operates below the OS, so physical "
            f"acquisition is a candidate at every lock state. Whether the "
            f"resulting image is *readable* still depends on encryption.")

    # Unencrypted or FDE Android is where a physical image is actually useful.
    if scheme in ("none", "FDE") and "physical" not in methods["unlocked"]:
        methods["unlocked"].insert(0, "physical")
        methods["afu"].insert(0, "physical")
        reasoning.append(
            f"{scheme} storage means a physical image is likely decryptable.")

    if family and family.secure_element:
        reasoning.append(
            f"Hardware secure element present ({family.secure_element}); "
            f"passcode attempts are rate-limited in silicon.")

    return Inference(
        os_family=os_name or "unknown",
        chipset=chipset or "unknown",
        family=family,
        encryption=scheme,
        methods=methods,
        reasoning=reasoning,
        confidence=min(confidence, 0.75),   # never rivals a catalogued entry
    )


def family_report() -> Dict[str, Any]:
    """The chipset families ARGUS reasons about, for the compatibility page."""
    return {
        "families": [
            {"name": f.name, "vendor": f.vendor,
             "bootrom_exploit": f.bootrom_exploit,
             "exploit": f.exploit_name, "secure_element": f.secure_element,
             "note": f.note}
            for f in CHIPSET_FAMILIES
        ],
        "count": len(CHIPSET_FAMILIES),
        "note": ("Used to derive a profile when a handset is not catalogued. "
                 "Inferred profiles are always labelled as such and never "
                 "outrank a tested catalogue entry."),
    }
