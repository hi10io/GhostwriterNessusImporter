from enum import Enum
from dataclasses import dataclass
from lib.utils.cvss_vector import process_cvss_vector


class Severity(Enum):
    INFO = 1, "info"
    LOW = 2, "low"
    MEDIUM = 3, "medium"
    HIGH = 4, "high"
    CRITICAL = 5, "critical"

    def __new__(cls, *values):
        assert len(values) > 0
        obj = object.__new__(cls)
        obj._value_ = values[0]
        for other_value in values[1:]:
            cls._value2member_map_[other_value] = obj
        obj._all_values = values
        return obj

    def __repr__(self):
        return "<%s.%s: %s>" % (
            self.__class__.__name__,
            self._name_,
            ", ".join([repr(v) for v in self._all_values]),
        )


@dataclass
class SeverityData:
    severity: Severity
    cvss_score: float
    cvss_vector: str

    def __repr__(self):
        return f"<SeverityData {self.severity}: CVSS={self.cvss_score}, Vector={self.cvss_vector}>"


@staticmethod
def from_cvss(cvss_score: float, cvss_vector: str, title: str):
    """Creates a SeverityData instance without modifying shared Severity enum instances."""

    if cvss_score == 0.0:
        severity = Severity.INFO
    elif 0.0 < cvss_score < 4:
        severity = Severity.LOW
    elif 4 <= cvss_score < 7:
        severity = Severity.MEDIUM
    elif 7 <= cvss_score < 9:
        severity = Severity.HIGH  
    elif 9 <= cvss_score <= 10:
        severity = Severity.CRITICAL
    else:
        raise ValueError(f"Invalid CVSS score: {cvss_score}")

    if not isinstance(cvss_vector, list):
        if not isinstance(cvss_vector, str):
            raise ValueError(f"Invalid CVSS vector: {cvss_vector}")
        if "," in cvss_vector:
            cvss_vector = cvss_vector.split(",")
        elif "/" in cvss_vector:
            cvss_vector = cvss_vector.split("/")

    processed_vector = process_cvss_vector(cvss_vector)

    return SeverityData(severity, cvss_score, processed_vector)
