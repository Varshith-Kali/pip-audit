"""
Functionality for formatting vulnerability results as SARIF.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit import __version__

from .interface import VulnerabilityFormat, vuln_id_url

logger = logging.getLogger(__name__)

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_INFORMATION_URI = "https://github.com/pypa/pip-audit"

# `shortDescription` is rendered prominently by SARIF consumers (for example, in
# alert lists), so we keep it to the description's first line and cap its length
# to avoid bloating rule metadata with multi-paragraph descriptions.
_SHORT_DESCRIPTION_MAX_LENGTH = 256


class SarifFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as
    SARIF 2.1.0.

    Each distinct vulnerability becomes a SARIF rule, and each
    (dependency, vulnerability) pair becomes a result that references its rule.

    Source locations (`physicalLocation`) are intentionally omitted: pip-audit's
    dependency model does not track the file, line, and column where each
    dependency was declared, and some audit sources (like the local environment)
    have no such location at all. Results without locations are valid per the
    SARIF 2.1.0 schema; populating locations is future work, pending
    source-location tracking in the dependency model.
    """

    def __init__(self, output_desc: bool, output_aliases: bool) -> None:
        """
        Create a new `SarifFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability
        should be included in the output as they can be quite long and make the output
        difficult to read.

        `output_aliases` is a flag to determine whether aliases (such as CVEs) for each
        vulnerability should be included in the output.
        """
        self.output_desc = output_desc
        self.output_aliases = output_aliases

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return True

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:
        """
        Returns a SARIF formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        if fixes:
            logger.warning("--fix output is unsupported by the SARIF format")

        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for dep, vulns in result.items():
            # Like the CycloneDX format, skipped dependencies are omitted: there is
            # no natural SARIF representation for "could not be audited".
            if dep.is_skipped():
                continue

            dep = cast(service.ResolvedDependency, dep)
            for vuln in vulns:
                if vuln.id not in rules:
                    rules[vuln.id] = self._format_rule(vuln)
                results.append(self._format_result(dep, vuln))

        output = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pip-audit",
                            "version": __version__,
                            "informationUri": _TOOL_INFORMATION_URI,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(output)

    def _format_rule(self, vuln: service.VulnerabilityResult) -> dict[str, Any]:
        short_description = vuln.id
        if self.output_desc and vuln.description:
            short_description = vuln.description.splitlines()[0][:_SHORT_DESCRIPTION_MAX_LENGTH]

        rule: dict[str, Any] = {
            "id": vuln.id,
            "shortDescription": {"text": short_description},
            "helpUri": vuln_id_url(vuln.id),
        }
        if self.output_desc and vuln.description:
            rule["fullDescription"] = {"text": vuln.description}

        properties: dict[str, Any] = {}
        if vuln.fix_versions:
            properties["fixVersions"] = [str(version) for version in vuln.fix_versions]
        if self.output_aliases and vuln.aliases:
            properties["aliases"] = sorted(vuln.aliases)
        if properties:
            rule["properties"] = properties

        return rule

    def _format_result(
        self, dep: service.ResolvedDependency, vuln: service.VulnerabilityResult
    ) -> dict[str, Any]:
        message = f"{dep.canonical_name} ({dep.version}) is vulnerable to {vuln.id}"
        if self.output_desc and vuln.description:
            message = f"{message}: {vuln.description}"

        return {
            "ruleId": vuln.id,
            "level": "error",
            "message": {"text": message},
            "properties": {
                "package": dep.canonical_name,
                "version": str(dep.version),
            },
        }
