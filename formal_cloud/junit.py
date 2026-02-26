from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def certificate_to_junit_xml(certificate: dict[str, Any], include_waived: bool = False) -> str:
    testsuite = ET.Element(
        "testsuite",
        name="FormalCloud",
        tests="0",
        failures="0",
        skipped="0",
    )

    tests = 0
    failures = 0
    skipped = 0

    for result in certificate.get("results") or []:
        rule_id = str(result.get("id", "UNKNOWN"))
        title = str(result.get("title", rule_id))

        for violation in result.get("violations") or []:
            tests += 1
            failures += 1
            testcase = ET.SubElement(
                testsuite,
                "testcase",
                classname="FormalCloud.Policy",
                name=f"{rule_id}:{violation.get('entity')}",
            )
            failure = ET.SubElement(
                testcase,
                "failure",
                message=str(violation.get("message", "policy violation")),
                type=str(result.get("severity", "medium")),
            )
            failure.text = (
                f"rule={rule_id} title={title} "
                f"entity={violation.get('entity')} details={violation.get('details')}"
            )

        if include_waived:
            for violation in result.get("waived_violations") or []:
                tests += 1
                skipped += 1
                testcase = ET.SubElement(
                    testsuite,
                    "testcase",
                    classname="FormalCloud.Policy",
                    name=f"{rule_id}:{violation.get('entity')}:waived",
                )
                skip = ET.SubElement(
                    testcase,
                    "skipped",
                    message="waived by approved exception",
                )
                skip.text = str(violation.get("message", "waived violation"))

    testsuite.set("tests", str(tests))
    testsuite.set("failures", str(failures))
    testsuite.set("skipped", str(skipped))

    xml_text = ET.tostring(testsuite, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_text + "\n"
