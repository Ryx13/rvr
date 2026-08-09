"""
RVR — Conditional module registry
Declares, in one place, which modules exist and what open-port condition
triggers each one. core.py reads this list instead of hard-coding an
if/elif chain plus a matching _phase_* method per module — adding a new
conditional module now means adding one entry here, not three edits
scattered across core.py.

Imports are deliberately deferred (string path + class name, resolved via
importlib only when a module actually triggers) so that a module with a
heavy/optional dependency doesn't slow down or risk breaking startup for
scans that never trigger it.
"""

import importlib
from dataclasses import dataclass
from typing import Callable

from rvr.utils.state import RVRState


@dataclass(frozen=True)
class ModuleSpec:
    name: str            # matches --skip value and log label
    module_path: str      # e.g. "rvr.modules.ftp"
    class_name: str       # e.g. "FTPModule"
    trigger: Callable[[RVRState], bool]
    description: str = ""


CONDITIONAL_MODULES = [
    ModuleSpec(
        name="web",
        module_path="rvr.modules.web",
        class_name="WebModule",
        trigger=lambda s: bool(s.get_web_ports()),
        description="Any common web port open",
    ),
    ModuleSpec(
        name="smb",
        module_path="rvr.modules.smb",
        class_name="SMBModule",
        trigger=lambda s: s.has_any_port(139, 445),
        description="SMB ports 139/445 open",
    ),
    ModuleSpec(
        name="nfs",
        module_path="rvr.modules.nfs",
        class_name="NFSModule",
        trigger=lambda s: s.has_any_port(111, 2049),
        description="NFS/RPC ports 111/2049 open",
    ),
    ModuleSpec(
        name="snmp",
        module_path="rvr.modules.snmp",
        class_name="SNMPModule",
        trigger=lambda s: s.has_port(161),
        description="SNMP port 161 open",
    ),
    ModuleSpec(
        name="ftp",
        module_path="rvr.modules.ftp",
        class_name="FTPModule",
        trigger=lambda s: s.has_port(21),
        description="FTP port 21 open",
    ),
    ModuleSpec(
        name="databases",
        module_path="rvr.modules.databases",
        class_name="DatabaseModule",
        trigger=lambda s: s.has_any_port(3306, 1433, 5432, 6379, 27017),
        description="A known database port open (MySQL/MSSQL/PostgreSQL/Redis/MongoDB)",
    ),
    ModuleSpec(
        name="ldap",
        module_path="rvr.modules.ldap_enum",
        class_name="LDAPModule",
        trigger=lambda s: s.has_any_port(389, 636, 3268, 3269),
        description="LDAP/AD ports 389/636/3268/3269 open",
    ),
    ModuleSpec(
        name="rdp",
        module_path="rvr.modules.rdp",
        class_name="RDPModule",
        trigger=lambda s: s.has_port(3389),
        description="RDP port 3389 open",
    ),
]


def load_module_class(spec: ModuleSpec):
    """Resolve a ModuleSpec's class lazily, only when it's actually going to run."""
    mod = importlib.import_module(spec.module_path)
    return getattr(mod, spec.class_name)


def get_triggered_modules(state: RVRState) -> list:
    """Return the ModuleSpecs whose trigger condition matches current state,
    excluding anything the user passed via --skip."""
    return [
        spec for spec in CONDITIONAL_MODULES
        if spec.name not in state.skip and spec.trigger(state)
    ]