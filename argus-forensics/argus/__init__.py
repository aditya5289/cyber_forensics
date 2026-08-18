"""ARGUS Forensics — mobile device acquisition and analysis toolkit.

A two-part suite mirroring the workflow in the MSAB XRY/XAMN lab manual:

``argus.acquire``  the XRY half — device support verification, case creation,
                   logical / file-system / backup extraction, live logging.
``argus.analyze``  the XAMN half — timeline, connection graph, query language,
                   tagging, and report generation.

Everything in between is held in an EvidenceContainer — a sealed, hash-chained,
content-addressed evidence unit.

Quick start::

    from argus.core.case import Case, Exhibit
    from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan

    case = Case.create("./cases", investigator="A. Sharma")
    case.add_exhibit(Exhibit("EXH-001", make="Apple", model="iPhone 12 mini"))
    plan = AcquisitionPlan(method="import", source_path=Path("./backup"),
                           operator="A. Sharma", exhibit_id="EXH-001")
    report = AcquisitionEngine(case).run(plan)
"""

__version__ = "1.2.0"
__author__ = "ARGUS Forensics"
__license__ = "MIT"

from .core.errors import (ArgusError, AcquisitionError, CaseError,
                          ContainerError, IntegrityError, ParserError,
                          QueryError, ReportError)

__all__ = [
    "__version__",
    "ArgusError", "AcquisitionError", "CaseError", "ContainerError",
    "IntegrityError", "ParserError", "QueryError", "ReportError",
]
