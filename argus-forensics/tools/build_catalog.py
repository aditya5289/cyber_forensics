"""Generate argus/devices/catalog.json from a compact device table.

The table below is kept terse on purpose. Capability matrices are derived from
the OS release and chipset family rather than written out per device, because
hand-maintaining a matrix for several hundred handsets guarantees they drift
apart and an examiner ends up trusting a stale cell.

Run:  python3 tools/build_catalog.py
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from argus.devices.families import android_encryption, identify_chipset

OUT = pathlib.Path(__file__).resolve().parents[1] / "argus/devices/catalog.json"

# (model, aliases, os_versions, chipset, released, connector)
Row = Tuple[str, str, str, str, str, str]

APPLE: List[Row] = [
    ("iPhone 6s", "iPhone8,1|A1688", "9 - 15", "Apple A9", "2015-09", "Lightning"),
    ("iPhone 7", "iPhone9,1|A1660", "10 - 15", "Apple A10 Fusion", "2016-09", "Lightning"),
    ("iPhone 8", "iPhone10,1|A1863", "11 - 16", "Apple A11 Bionic", "2017-09", "Lightning"),
    ("iPhone X", "iPhone10,3|A1865", "11 - 16", "Apple A11 Bionic", "2017-11", "Lightning"),
    ("iPhone XR", "iPhone11,8|A1984", "12 - 18", "Apple A12 Bionic", "2018-10", "Lightning"),
    ("iPhone XS", "iPhone11,2|A1920", "12 - 18", "Apple A12 Bionic", "2018-09", "Lightning"),
    ("iPhone 11", "iPhone12,1|A2111", "13 - 18", "Apple A13 Bionic", "2019-09", "Lightning"),
    ("iPhone 11 Pro", "iPhone12,3|A2160", "13 - 18", "Apple A13 Bionic", "2019-09", "Lightning"),
    ("iPhone SE (2020)", "iPhone12,8|A2275", "13 - 18", "Apple A13 Bionic", "2020-04", "Lightning"),
    ("iPhone 12 mini", "iPhone13,1|A2176", "14 - 18", "Apple A14 Bionic", "2020-11", "Lightning"),
    ("iPhone 12", "iPhone13,2|A2172", "14 - 18", "Apple A14 Bionic", "2020-10", "Lightning"),
    ("iPhone 12 Pro", "iPhone13,3|A2341", "14 - 18", "Apple A14 Bionic", "2020-10", "Lightning"),
    ("iPhone 12 Pro Max", "iPhone13,4|A2342", "14 - 18", "Apple A14 Bionic", "2020-11", "Lightning"),
    ("iPhone 13 mini", "iPhone14,4|A2481", "15 - 18", "Apple A15 Bionic", "2021-09", "Lightning"),
    ("iPhone 13", "iPhone14,5|A2482", "15 - 18", "Apple A15 Bionic", "2021-09", "Lightning"),
    ("iPhone 13 Pro", "iPhone14,2|A2483", "15 - 18", "Apple A15 Bionic", "2021-09", "Lightning"),
    ("iPhone SE (2022)", "iPhone14,6|A2595", "15 - 18", "Apple A15 Bionic", "2022-03", "Lightning"),
    ("iPhone 14", "iPhone14,7|A2649", "16 - 18", "Apple A15 Bionic", "2022-09", "Lightning"),
    ("iPhone 14 Pro", "iPhone15,2|A2650", "16 - 18", "Apple A16 Bionic", "2022-09", "Lightning"),
    ("iPhone 14 Pro Max", "iPhone15,3|A2651", "16 - 18", "Apple A16 Bionic", "2022-09", "Lightning"),
    ("iPhone 15", "iPhone15,4|A3090", "17 - 18", "Apple A16 Bionic", "2023-09", "USB-C"),
    ("iPhone 15 Pro", "iPhone16,1|A3101", "17 - 18", "Apple A17 Pro", "2023-09", "USB-C"),
    ("iPhone 15 Pro Max", "iPhone16,2|A3102", "17 - 18", "Apple A17 Pro", "2023-09", "USB-C"),
    ("iPhone 16", "iPhone17,3|A3081", "18", "Apple A18", "2024-09", "USB-C"),
    ("iPhone 16 Pro", "iPhone17,1|A3083", "18", "Apple A18 Pro", "2024-09", "USB-C"),
    ("iPad (9th gen)", "iPad12,1|A2602", "15 - 18", "Apple A13 Bionic", "2021-09", "Lightning"),
    ("iPad Air (5th gen)", "iPad13,16|A2588", "15 - 18", "Apple M1", "2022-03", "USB-C"),
    ("iPad Pro 11 (M2)", "iPad14,3|A2759", "16 - 18", "Apple M2", "2022-10", "USB-C"),
]

SAMSUNG: List[Row] = [
    ("Galaxy S7", "SM-G930F|herolte", "6 - 8", "Exynos 8890", "2016-03", "Micro-USB"),
    ("Galaxy S8", "SM-G950F|dreamlte", "7 - 9", "Exynos 8895", "2017-04", "USB-C"),
    ("Galaxy S9", "SM-G960F|starlte", "8 - 10", "Exynos 9810", "2018-03", "USB-C"),
    ("Galaxy S10", "SM-G973F|beyond1lte", "9 - 12", "Exynos 9820", "2019-03", "USB-C"),
    ("Galaxy S20", "SM-G980F|x1s", "10 - 13", "Exynos 990", "2020-03", "USB-C"),
    ("Galaxy S21 5G", "SM-G991B|o1s", "11 - 14", "Exynos 2100", "2021-01", "USB-C"),
    ("Galaxy S22", "SM-S901B|r0s", "12 - 15", "Exynos 2200", "2022-02", "USB-C"),
    ("Galaxy S23", "SM-S911B|dm1q", "13 - 15", "Snapdragon 8 Gen 2", "2023-02", "USB-C"),
    ("Galaxy S24", "SM-S921B|e1s", "14 - 15", "Exynos 2400", "2024-01", "USB-C"),
    ("Galaxy S24 Ultra", "SM-S928B|e3q", "14 - 15", "Snapdragon 8 Gen 3", "2024-01", "USB-C"),
    ("Galaxy Note 9", "SM-N960F|crownlte", "8 - 10", "Exynos 9810", "2018-08", "USB-C"),
    ("Galaxy Note 20", "SM-N980F|c1s", "10 - 13", "Exynos 990", "2020-08", "USB-C"),
    ("Galaxy A12", "SM-A125F|a12", "10 - 12", "MediaTek Helio P35", "2020-11", "Micro-USB"),
    ("Galaxy A13", "SM-A135F|a13", "12 - 14", "MediaTek Helio G80", "2022-03", "USB-C"),
    ("Galaxy A14", "SM-A145F|a14", "13 - 15", "MediaTek Helio G80", "2023-01", "USB-C"),
    ("Galaxy A32", "SM-A325F|a32", "11 - 13", "MediaTek Helio G80", "2021-03", "USB-C"),
    ("Galaxy A50", "SM-A505F|a50", "9 - 11", "Exynos 9610", "2019-03", "USB-C"),
    ("Galaxy A52", "SM-A525F|a52q", "11 - 13", "Snapdragon 720G", "2021-03", "USB-C"),
    ("Galaxy A54", "SM-A546B|a54x", "13 - 15", "Exynos 1380", "2023-03", "USB-C"),
    ("Galaxy A71", "SM-A715F|a71", "10 - 12", "Snapdragon 730", "2020-01", "USB-C"),
    ("Galaxy J5", "SM-J500F|j5lte", "5.1 - 7", "Snapdragon 410", "2015-06", "Micro-USB"),
    ("Galaxy J7", "SM-J700F|j7elte", "5.1 - 8.1", "Exynos 7580", "2015-06", "Micro-USB"),
    ("Galaxy M31", "SM-M315F|m31", "10 - 12", "Exynos 9611", "2020-02", "USB-C"),
    ("Galaxy Z Flip 5", "SM-F731B|b5q", "13 - 15", "Snapdragon 8 Gen 2", "2023-08", "USB-C"),
    ("Galaxy Z Fold 5", "SM-F946B|q5q", "13 - 15", "Snapdragon 8 Gen 2", "2023-08", "USB-C"),
    ("Galaxy Tab A8", "SM-X200|gta8wifi", "11 - 14", "Unisoc T618", "2021-12", "USB-C"),
]

XIAOMI: List[Row] = [
    ("Redmi Note 8", "M1908C3JG|ginkgo", "9 - 11", "Snapdragon 665", "2019-08", "Micro-USB"),
    ("Redmi Note 9", "M2003J15SC|merlin", "10 - 12", "MediaTek Helio G85", "2020-04", "USB-C"),
    ("Redmi Note 10", "M2101K7AI|mojito", "11 - 13", "Snapdragon 678", "2021-03", "USB-C"),
    ("Redmi Note 11", "2201117TG|spes", "11 - 14", "Snapdragon 680", "2022-01", "USB-C"),
    ("Redmi Note 12", "23021RAAEG|tapas", "12 - 14", "Snapdragon 685", "2023-03", "USB-C"),
    ("Redmi Note 13", "23129RAA4G|sapphire", "13 - 15", "MediaTek Dimensity 6080", "2024-01", "USB-C"),
    ("Redmi 9A", "M2006C3LG|dandelion", "10 - 12", "MediaTek Helio G25", "2020-06", "Micro-USB"),
    ("Redmi 10", "21061119AG|selene", "11 - 13", "MediaTek Helio G88", "2021-08", "USB-C"),
    ("Mi 9", "M1902F1G|cepheus", "9 - 11", "Snapdragon 855", "2019-02", "USB-C"),
    ("Mi 11", "M2011K2G|venus", "11 - 14", "Snapdragon 888", "2021-01", "USB-C"),
    ("Xiaomi 12", "2201123G|cupid", "12 - 15", "Snapdragon 8 Gen 1", "2021-12", "USB-C"),
    ("Xiaomi 13", "2211133G|fuxi", "13 - 15", "Snapdragon 8 Gen 2", "2022-12", "USB-C"),
    ("Xiaomi 14", "23127PN0CG|houji", "14 - 15", "Snapdragon 8 Gen 3", "2023-10", "USB-C"),
    ("Poco X3 Pro", "M2102J20SG|vayu", "11 - 13", "Snapdragon 860", "2021-03", "USB-C"),
    ("Poco F5", "23049PCD8G|marble", "13 - 15", "Snapdragon 7+ Gen 2", "2023-05", "USB-C"),
]

OPPO_VIVO_REALME: List[Row] = [
    ("Oppo A54", "CPH2239", "10 - 12", "MediaTek Helio P35", "2021-03", "Micro-USB"),
    ("Oppo A78", "CPH2565", "13 - 14", "Snapdragon 680", "2023-04", "USB-C"),
    ("Oppo Reno 6", "CPH2235", "11 - 13", "MediaTek Dimensity 900", "2021-05", "USB-C"),
    ("Oppo Reno 8", "CPH2359", "12 - 14", "MediaTek Dimensity 1300", "2022-05", "USB-C"),
    ("Oppo Find X5", "CPH2307", "12 - 14", "Snapdragon 8 Gen 1", "2022-02", "USB-C"),
    ("Vivo Y21", "V2111", "11 - 13", "MediaTek Helio P35", "2021-08", "Micro-USB"),
    ("Vivo Y35", "V2205", "12 - 14", "Snapdragon 680", "2022-09", "USB-C"),
    ("Vivo V25", "V2202", "12 - 14", "MediaTek Dimensity 900", "2022-08", "USB-C"),
    ("Vivo X80", "V2183A", "12 - 14", "MediaTek Dimensity 9000", "2022-04", "USB-C"),
    ("Realme C11", "RMX2185", "10 - 11", "MediaTek Helio G35", "2020-06", "Micro-USB"),
    ("Realme 8", "RMX3085", "11 - 12", "MediaTek Helio G95", "2021-03", "USB-C"),
    ("Realme 9 Pro", "RMX3471", "12 - 14", "Snapdragon 695", "2022-02", "USB-C"),
    ("Realme 11 Pro", "RMX3771", "13 - 14", "MediaTek Dimensity 7050", "2023-05", "USB-C"),
    ("Realme GT 2", "RMX3311", "12 - 14", "Snapdragon 888", "2022-01", "USB-C"),
]

OTHER_ANDROID: List[Row] = [
    ("Pixel 4a", "G025J|sunfish", "10 - 13", "Snapdragon 730G", "2020-08", "USB-C"),
    ("Pixel 5", "GD1YQ|redfin", "11 - 14", "Snapdragon 765G", "2020-10", "USB-C"),
    ("Pixel 6", "GB7N6|oriole", "12 - 15", "Google Tensor", "2021-10", "USB-C"),
    ("Pixel 7", "GVU6C|panther", "13 - 15", "Google Tensor G2", "2022-10", "USB-C"),
    ("Pixel 8", "GKWS6|shiba", "14 - 15", "Google Tensor G3", "2023-10", "USB-C"),
    ("Pixel 9 Pro", "GE2AE|caiman", "15", "Google Tensor G4", "2024-08", "USB-C"),
    ("OnePlus 7 Pro", "GM1913|guacamole", "9 - 12", "Snapdragon 855", "2019-05", "USB-C"),
    ("OnePlus 9", "LE2113|lemonade", "11 - 14", "Snapdragon 888", "2021-03", "USB-C"),
    ("OnePlus Nord CE 2", "IV2201", "11 - 13", "MediaTek Dimensity 900", "2022-02", "USB-C"),
    ("OnePlus 11", "CPH2449|salami", "13 - 15", "Snapdragon 8 Gen 2", "2023-01", "USB-C"),
    ("Moto G54", "XT2343", "13 - 14", "MediaTek Dimensity 7020", "2023-09", "USB-C"),
    ("Moto G84", "XT2347", "13 - 14", "Snapdragon 695", "2023-09", "USB-C"),
    ("Moto E13", "XT2345", "13", "Unisoc T606", "2023-02", "USB-C"),
    ("Motorola Edge 40", "XT2303", "13 - 14", "MediaTek Dimensity 8020", "2023-05", "USB-C"),
    ("Huawei P30 Lite", "MAR-LX1A", "9 - 10", "Kirin 710", "2019-03", "USB-C"),
    ("Huawei P40", "ANA-NX9", "10 - 12", "Kirin 990", "2020-03", "USB-C"),
    ("Honor 9X", "STK-LX1", "9 - 10", "Kirin 710F", "2019-07", "Micro-USB"),
    ("Honor X8", "TFY-LX1", "11 - 12", "Snapdragon 680", "2022-03", "USB-C"),
    ("Nothing Phone (2)", "A065", "13 - 15", "Snapdragon 8+ Gen 1", "2023-07", "USB-C"),
    ("Sony Xperia 1 III", "XQ-BC52", "11 - 13", "Snapdragon 888", "2021-07", "USB-C"),
    ("Sony Xperia 10 IV", "XQ-CC54", "12 - 14", "Snapdragon 695", "2022-05", "USB-C"),
    ("Asus Zenfone 9", "AI2202", "12 - 14", "Snapdragon 8+ Gen 1", "2022-07", "USB-C"),
    ("LG G8 ThinQ", "LM-G820", "9 - 11", "Snapdragon 855", "2019-03", "USB-C"),
    ("LG K52", "LM-K520", "10 - 11", "MediaTek Helio P35", "2020-10", "USB-C"),
    ("Tecno Spark 10", "KI5q", "13", "MediaTek Helio G88", "2023-04", "USB-C"),
    ("Tecno Camon 20", "CK6n", "13", "MediaTek Helio G85", "2023-05", "USB-C"),
    ("Infinix Hot 30", "X6831", "12 - 13", "MediaTek Helio G88", "2023-03", "USB-C"),
    ("Infinix Note 30", "X6833B", "13", "MediaTek Helio G99", "2023-05", "USB-C"),
    ("itel A60s", "A101", "12", "Unisoc SC9863A", "2023-06", "Micro-USB"),
    ("Lava Blaze 2", "LZX405", "13", "MediaTek Helio G37", "2023-04", "USB-C"),
    ("Micromax IN 2b", "E6746", "11 - 12", "Unisoc T610", "2021-08", "USB-C"),
    ("Nokia G21", "TA-1418", "11 - 13", "Unisoc T606", "2022-02", "USB-C"),
    ("Nokia XR20", "TA-1362", "11 - 13", "Snapdragon 480", "2021-07", "USB-C"),
]

FEATURE_PHONES: List[Row] = [
    ("Nokia 105 (2019)", "TA-1174", "n/a", "MediaTek MT6261", "2019-07", "Micro-USB"),
    ("Nokia 106 (2023)", "TA-1564", "n/a", "Unisoc 6531F", "2023-06", "Micro-USB"),
    ("Nokia 3310 (2017)", "TA-1030", "n/a", "MediaTek MT6260", "2017-05", "Micro-USB"),
    ("Nokia 8110 4G", "TA-1048", "KaiOS 2.5", "Snapdragon 205", "2018-05", "Micro-USB"),
    ("JioPhone 2", "F300B", "KaiOS 2.5", "Spreadtrum SC9820", "2018-08", "Micro-USB"),
    ("Alcatel 3082", "3082X", "n/a", "MediaTek MT6261", "2020-01", "Micro-USB"),
    ("Samsung Guru Music 2", "SM-B310E", "n/a", "MediaTek MT6260", "2015-03", "Micro-USB"),
]

WEARABLES: List[Row] = [
    ("Apple Watch Series 7", "Watch6,6|A2473", "watchOS 8 - 10", "Apple S7", "2021-10", "Magnetic"),
    ("Apple Watch SE (2022)", "Watch6,10|A2722", "watchOS 9 - 10", "Apple S8", "2022-09", "Magnetic"),
    ("Galaxy Watch 5", "SM-R900", "Wear OS 3.5", "Exynos W920", "2022-08", "Magnetic"),
    ("Fitbit Versa 3", "FB511", "Fitbit OS 5", "n/a", "2020-09", "Proprietary"),
]

VENDORS: List[Tuple[str, str, List[Row]]] = [
    ("Apple", "iOS", APPLE),
    ("Samsung", "Android", SAMSUNG),
    ("Xiaomi", "Android", XIAOMI),
    ("", "Android", OPPO_VIVO_REALME),
    ("", "Android", OTHER_ANDROID),
    ("", "Feature phone", FEATURE_PHONES),
    ("", "Wearable", WEARABLES),
]

BRANDS = ["Samsung", "Xiaomi", "Redmi", "Poco", "Oppo", "Vivo", "Realme",
          "Pixel", "OnePlus", "Motorola", "Moto", "Huawei", "Honor", "Nothing",
          "Sony", "Asus", "LG", "Tecno", "Infinix", "itel", "Lava", "Micromax",
          "Nokia", "JioPhone", "Alcatel", "Apple", "Galaxy", "Fitbit", "iPhone",
          "iPad", "Mi"]

BRAND_OWNER = {"Redmi": "Xiaomi", "Poco": "Xiaomi", "Mi": "Xiaomi",
               "Pixel": "Google", "Moto": "Motorola", "Galaxy": "Samsung",
               "JioPhone": "Reliance", "iPhone": "Apple", "iPad": "Apple"}


def split_make(model: str, default: str) -> Tuple[str, str]:
    """Resolve the manufacturer from a marketing name."""
    if default:
        return default, model
    for brand in BRANDS:
        if model == brand or model.startswith(brand + " "):
            make = BRAND_OWNER.get(brand, brand)
            # Keep the product line in the model when it is not the maker name,
            # so "Redmi Note 10" does not collapse to "Note 10".
            return make, model if brand != make else model[len(brand):].strip()
    return "Unknown", model


def lowest_version(spec: str) -> float:
    found = re.findall(r"\d+(?:\.\d+)?", spec or "")
    return float(found[0]) if found else 0.0


def capabilities(os_family: str, versions: str, chipset: str
                 ) -> List[Dict[str, Any]]:
    """Derive the matrix from what actually governs it."""
    family = identify_chipset(chipset)
    low = lowest_version(versions)
    caps: List[Dict[str, Any]] = []

    def add(state: str, method: str, note: str = "") -> None:
        caps.append({"lock_state": state, "method": method,
                     "supported": True, "note": note, "requires": []})

    is_ios = os_family in ("iOS", "Wearable") and "Apple" in chipset

    if os_family == "Feature phone" and "KaiOS" not in versions:
        add("unlocked", "logical",
            "Feature phone: contacts, SMS and call log only. No application "
            "data or file system in the smartphone sense.")
        for state in ("unlocked", "afu", "bfu", "locked"):
            add(state, "sim")
            add(state, "screenshot")
        if family and family.bootrom_exploit:
            for state in ("unlocked", "locked"):
                add(state, "physical",
                    f"{family.exploit_name} operates below the OS and storage "
                    f"on these handsets is normally unencrypted, so a full "
                    f"readable image is realistic.")
        return caps

    for state in ("unlocked", "afu", "bfu", "locked"):
        add(state, "sim")
        add(state, "screenshot")

    add("unlocked", "logical",
        "Requires the device to be trusted by this workstation." if is_ios
        else "Requires USB debugging enabled and the workstation key authorised.")
    add("unlocked", "backup",
        "iTunes backup; an encrypted backup needs the password." if is_ios
        else "adb backup is deprecated from Android 12 and many apps opt out.")
    add("unlocked", "filesystem",
        "Full read requires a jailbreak or an agent." if is_ios
        else "Full /data access requires root or a vendor service exploit.")
    add("unlocked", "cloud", "Requires separate legal authority.")
    add("afu", "logical", "")
    add("afu", "backup", "")

    if is_ios:
        if family and family.bootrom_exploit:
            for state in ("unlocked", "afu", "bfu", "locked"):
                add(state, "physical",
                    "checkm8 is a BootROM flaw and cannot be patched, so "
                    "imaging succeeds at any lock state. The image stays "
                    "encrypted without the passcode.")
        return caps

    scheme, consequence = android_encryption(low)
    if scheme in ("none", "FDE"):
        for state in ("unlocked", "afu", "bfu", "locked"):
            add(state, "physical", consequence)
    elif family and family.bootrom_exploit:
        for state in ("unlocked", "afu", "bfu", "locked"):
            add(state, "physical",
                f"{family.exploit_name} yields an image at any lock state, but "
                f"file-based encryption keeps user data wrapped until first "
                f"unlock, so a BFU image carries little content.")
    return caps


def build() -> Dict[str, Any]:
    devices: List[Dict[str, Any]] = []
    seen = set()
    for default_make, os_family, rows in VENDORS:
        for model, aliases, versions, chipset, released, connector in rows:
            make, short = split_make(model, default_make)
            resolved_os = os_family
            if os_family == "Wearable":
                resolved_os = "watchOS" if make == "Apple" else "Wear OS"
                if "Fitbit" in chipset or make == "Fitbit":
                    resolved_os = "Fitbit OS"
            elif "KaiOS" in versions:
                resolved_os = "KaiOS"
            key = (make.lower(), short.lower())
            if key in seen:
                continue
            seen.add(key)
            alias_list = [a for a in aliases.split("|") if a]
            codename = ""
            if len(alias_list) > 1 and alias_list[-1].islower():
                codename = alias_list[-1]
            devices.append({
                "make": make,
                "model": short,
                "aliases": alias_list,
                "os_family": resolved_os,
                "os_versions": versions,
                "chipset": chipset,
                "codename": codename,
                "released": released,
                "connector": connector,
                "capabilities": capabilities(os_family, versions, chipset),
                "notes": "",
            })
    return {
        "version": 2,
        "note": ("Generated by tools/build_catalog.py. Capability matrices are "
                 "derived from OS release and chipset family rather than hand "
                 "written per device, so individual cells cannot drift out of "
                 "step with the rule that produced them."),
        "devices": devices,
    }


if __name__ == "__main__":
    data = build()
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False),
                   encoding="utf-8")
    print(f"wrote {OUT} with {len(data['devices'])} devices")
