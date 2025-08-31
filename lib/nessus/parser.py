from glob import glob
from lib.nessus.finding import NessusFinding
from lib.settings import settings
from lib.types.namespace import Namespace
from lib.utils.python import deep_update
from tenable.nessus import Nessus
from tenable.reports import NessusReportv2
import re


class NessusFileParser:

    def __init__(self):

        self._validate_input_settings()
        self._findings = {}

    def _validate_input_settings(self):
        assert any(
            [settings.nessus.directory, settings.nessus.get("files")]
        ), "Either Nessus directory or Nessus files must be set"

    @property
    def findings(self):
        return self._findings

    @property
    def nessus_dir(self):
        return settings.nessus.directory

    @property
    def nessus_files(self):
        if settings.nessus.get("files"):
            for f in settings.nessus.files:
                yield f
        else:
            for f in glob(f"{self.nessus_dir.strip('/')}/*.nessus"):
                yield f

    @staticmethod
    def has_severity(entry):
        return entry.get("severity") and entry.get("severity") > 0

    @staticmethod
    def read_report(report_path):
        with open(report_path) as nessus_file:
            report = NessusReportv2(report_path)
        yield from report

    @staticmethod
    def is_valid_entry(entry):
        if not NessusFileParser.has_severity(entry):
            return False
        if not (entry.get("pluginID") and entry.get("host-report-name")):
            return False
        if entry["host-report-name"] in settings.nessus.exclude_hosts:
            return False
        return True

    @staticmethod
    def is_hostonly_entity(entry):
        return (
            not (entry.get("port") or entry.get("protocol"))
            or entry.get("protocol") == "icmp"
            or str(entry.get("port")) == "0"
        )

    @staticmethod
    def get_entity_key(entry):
        if NessusFileParser.is_hostonly_entity(entry):
            return entry.get("host-report-name")
        suffix = f"({entry.get('protocol', 'any')} / {entry.get('port', 'any')})"
        return " ".join([entry.get("host-report-name"), suffix])

    def clear(self):
        del self._findings
        self._findings = {}

    def read_report_entries(self, ns=False):
        for file_path in self.nessus_files:
            for entry in filter(self.is_valid_entry, self.read_report(file_path)):
                yield Namespace.from_dict(entry) if ns else entry

    def get_nessus_findings(self):
        sorted_findings = sorted(
            self.findings.values(), key=lambda f: f["cvss_score"], reverse=True
        )
        return [NessusFinding.from_dict(val) for val in sorted_findings]

    def get_gw_findings(self):
        findings_list = []  # Initialize an empty list
        for f in self.get_nessus_findings():
            obj = f.to_ghostwriter_finding()
            findings_list.append(obj)
        return findings_list

        #return [f.to_ghostwriter_finding() for f in self.get_nessus_findings()]


    def read_findings(self):

        for entry in self.read_report_entries(ns=True):
            if not hasattr(entry, 'plugin_output'):
                entry.plugin_output = "No Output Specified"
            if not hasattr(entry, 'cvss_base_score'): 
                entry.cvss_base_score = float(0.0)

            if not hasattr(entry, 'cvss_vector'): 
                entry.cvss_vector = ""
            
            if hasattr(entry, 'cvss3_base_score'): 
                cvss3vectorraw = entry.cvss3_vector
                entry.cvss_vector = re.sub(r'CVSS:3\.0', 'CVSS:3.1', cvss3vectorraw)
                if "3.0" in str(entry.cvss3_base_score):
                    entry.cvss_base_score = float(3.1)  
                else:
                    entry.cvss_base_score = float(entry.cvss3_base_score)

            
            entry.cvss_base_score = float(entry.cvss_base_score) 
            self.findings[entry.pluginID] = deep_update(
                self.findings.get(entry.pluginID, {}),
                {
                    "title": entry.plugin_name,
                    "cvss_score": entry.cvss_base_score,
                    "cvss_vector": entry.cvss_vector,
                    "description": entry.description,
                    "mitigation": entry.solution,
                    "affected_entities": {
                        self.get_entity_key(entry): entry.plugin_output
                    },
                    "plugin_id": entry.pluginID,
                    "severity": entry.risk_factor,
                },
            )


        return self.findings
