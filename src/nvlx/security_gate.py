"""NVIDIA security bulletin/CVE gating for fleet upgrades."""
from __future__ import annotations
from dataclasses import asdict, dataclass
import re, urllib.request

@dataclass(frozen=True)
class SecurityFinding:
    source:str; cves:tuple[str,...]; severity:str; blocked:bool; reason:str
    def to_dict(self): return asdict(self)

DEFAULT_BULLETINS=("https://raw.githubusercontent.com/NVIDIA/product-security/main/2026/5857/5857.md",)
_RELEASE_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")

def _version_tuple(value: str | None) -> tuple[int, int, int] | None:
    """Accept only an exact canonical numeric exporter release version."""
    if not isinstance(value, str):
        return None
    match = _RELEASE_VERSION.fullmatch(value)
    if match is None:
        return None
    try:
        return int(match[1]), int(match[2]), int(match[3])
    except ValueError:
        # Python may reject excessively long integer components.
        return None

def evaluate_dcgm_exporter(version:str|None, *, threshold:str="4.8.2")->SecurityFinding:
    cves=("CVE-2026-47483",)
    minimum = _version_tuple(threshold)
    if minimum is None:
        return SecurityFinding(
            DEFAULT_BULLETINS[0], cves, "HIGH", True,
            "DCGM Exporter minimum fixed version invalid; expected canonical MAJOR.MINOR.PATCH",
        )
    parsed = _version_tuple(version)
    if parsed is None:
        unknown = version is None or (isinstance(version, str) and not version)
        reason = "DCGM Exporter version unknown" if unknown else (
            "DCGM Exporter version invalid; expected canonical MAJOR.MINOR.PATCH"
        )
        return SecurityFinding(DEFAULT_BULLETINS[0], cves, "HIGH", True, reason)
    blocked=parsed < minimum
    return SecurityFinding(DEFAULT_BULLETINS[0],cves,"HIGH",blocked,f"DCGM Exporter {version}; required >= {threshold}")

def bulletin_reachable(url:str)->bool:
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"nvlx-security-gate"})
        with urllib.request.urlopen(req,timeout=5) as r: return 200 <= getattr(r,"status",200) < 400
    except Exception: return False

def gate(dcgm_exporter_version:str|None, *, fail_closed:bool=True)->dict[str,object]:
    finding=evaluate_dcgm_exporter(dcgm_exporter_version)
    reachable=all(bulletin_reachable(u) for u in DEFAULT_BULLETINS)
    blocked=finding.blocked or (fail_closed and not reachable)
    reasons=[finding.reason]
    if not reachable: reasons.append("NVIDIA product-security source unavailable")
    return {"passed":not blocked,"sources":DEFAULT_BULLETINS,"findings":[finding.to_dict()],"reasons":reasons}
