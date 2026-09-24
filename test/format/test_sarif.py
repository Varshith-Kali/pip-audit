import json

import pretend  # type: ignore
import pytest

import pip_audit._format as format
import pip_audit._format.sarif as sarif
from pip_audit import __version__


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_sarif_manifest(output_desc, output_aliases):
    fmt = format.SarifFormat(output_desc, output_aliases)

    assert fmt.is_manifest


def test_sarif(vuln_data):
    sarif_format = format.SarifFormat(True, True)
    expected_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {"text": "The first vulnerability"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-0",
                                "fullDescription": {"text": "The first vulnerability"},
                                "properties": {
                                    "fixVersions": ["1.1", "1.4"],
                                    "aliases": ["CVE-0000-00000"],
                                },
                            },
                            {
                                "id": "VULN-1",
                                "shortDescription": {"text": "The second vulnerability"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-1",
                                "fullDescription": {"text": "The second vulnerability"},
                                "properties": {
                                    "fixVersions": ["1.0"],
                                    "aliases": ["CVE-0000-00001"],
                                },
                            },
                            {
                                "id": "VULN-2",
                                "shortDescription": {"text": "The third vulnerability"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-2",
                                "fullDescription": {"text": "The third vulnerability"},
                                "properties": {
                                    "aliases": ["CVE-0000-00002"],
                                },
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {
                            "text": "foo (1.0) is vulnerable to VULN-0: The first vulnerability"
                        },
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-1",
                        "level": "error",
                        "message": {
                            "text": "foo (1.0) is vulnerable to VULN-1: The second vulnerability"
                        },
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-2",
                        "level": "error",
                        "message": {
                            "text": "bar (0.1) is vulnerable to VULN-2: The third vulnerability"
                        },
                        "properties": {"package": "bar", "version": "0.1"},
                    },
                ],
            }
        ],
    }
    assert sarif_format.format(vuln_data, []) == json.dumps(expected_sarif)


def test_sarif_no_desc(vuln_data):
    sarif_format = format.SarifFormat(False, True)
    expected_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {"text": "VULN-0"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-0",
                                "properties": {
                                    "fixVersions": ["1.1", "1.4"],
                                    "aliases": ["CVE-0000-00000"],
                                },
                            },
                            {
                                "id": "VULN-1",
                                "shortDescription": {"text": "VULN-1"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-1",
                                "properties": {
                                    "fixVersions": ["1.0"],
                                    "aliases": ["CVE-0000-00001"],
                                },
                            },
                            {
                                "id": "VULN-2",
                                "shortDescription": {"text": "VULN-2"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-2",
                                "properties": {
                                    "aliases": ["CVE-0000-00002"],
                                },
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {"text": "foo (1.0) is vulnerable to VULN-0"},
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-1",
                        "level": "error",
                        "message": {"text": "foo (1.0) is vulnerable to VULN-1"},
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-2",
                        "level": "error",
                        "message": {"text": "bar (0.1) is vulnerable to VULN-2"},
                        "properties": {"package": "bar", "version": "0.1"},
                    },
                ],
            }
        ],
    }
    assert sarif_format.format(vuln_data, []) == json.dumps(expected_sarif)


def test_sarif_no_desc_no_aliases(vuln_data):
    sarif_format = format.SarifFormat(False, False)
    expected_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {"text": "VULN-0"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-0",
                                "properties": {
                                    "fixVersions": ["1.1", "1.4"],
                                },
                            },
                            {
                                "id": "VULN-1",
                                "shortDescription": {"text": "VULN-1"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-1",
                                "properties": {
                                    "fixVersions": ["1.0"],
                                },
                            },
                            {
                                "id": "VULN-2",
                                "shortDescription": {"text": "VULN-2"},
                                "helpUri": "https://osv.dev/vulnerability/VULN-2",
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {"text": "foo (1.0) is vulnerable to VULN-0"},
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-1",
                        "level": "error",
                        "message": {"text": "foo (1.0) is vulnerable to VULN-1"},
                        "properties": {"package": "foo", "version": "1.0"},
                    },
                    {
                        "ruleId": "VULN-2",
                        "level": "error",
                        "message": {"text": "bar (0.1) is vulnerable to VULN-2"},
                        "properties": {"package": "bar", "version": "0.1"},
                    },
                ],
            }
        ],
    }
    assert sarif_format.format(vuln_data, []) == json.dumps(expected_sarif)


def test_sarif_skipped_dep(vuln_data_skipped_dep):
    sarif_format = format.SarifFormat(False, True)
    payload = json.loads(sarif_format.format(vuln_data_skipped_dep, []))

    run = payload["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    # Like the CycloneDX format, skipped dependencies are omitted from SARIF output.
    assert [rule["id"] for rule in rules] == ["VULN-0"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "VULN-0"
    assert results[0]["properties"]["package"] == "foo"


def test_sarif_no_vulns(no_vuln_data):
    sarif_format = format.SarifFormat(True, True)
    payload = json.loads(sarif_format.format(no_vuln_data, []))

    # An audit with no findings is still a valid (empty) SARIF log.
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_sarif_fix(monkeypatch, vuln_data, fix_data):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(sarif, "logger", logger)

    sarif_format = format.SarifFormat(True, True)
    payload = json.loads(sarif_format.format(vuln_data, fix_data))

    # The SARIF format doesn't support fixes so we expect to log a warning
    assert len(logger.warning.calls) == 1

    # ... and to produce the same results as without fixes.
    assert len(payload["runs"][0]["results"]) == 3
