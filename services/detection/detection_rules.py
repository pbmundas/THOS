"""
SIGMA and YARA rule tools.

Phase 1: returns rule templates that the reasoning node can fill in.
Phase 3 extension point: connect to a real SIGMA rule repo (e.g.
SigmaHQ/sigma) mounted read-only, index it into 'sigma_kb' Chroma
collection, and support real rule -> query conversion via sigma-cli /
pySigma backends per target SIEM.
"""

SIGMA_TEMPLATE = """\
title: {title}
id: {rule_id}
status: experimental
description: {description}
logsource:
    category: {log_category}
detection:
    selection:
        {selection_field}: {selection_value}
    condition: selection
level: {level}
"""


def generate_sigma_skeleton(title: str, log_category: str, selection_field: str,
                            selection_value: str, level: str = "medium",
                            description: str = "", rule_id: str = "generated-0001") -> str:
    """Produce a bare-bones SIGMA rule skeleton for the hunter/LLM to refine."""
    return SIGMA_TEMPLATE.format(
        title=title,
        rule_id=rule_id,
        description=description or title,
        log_category=log_category,
        selection_field=selection_field,
        selection_value=selection_value,
        level=level,
    )


YARA_TEMPLATE = """\
rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "THOS"
    strings:
        {strings_block}
    condition:
        {condition}
}}
"""


def generate_yara_skeleton(rule_name: str, strings: dict, condition: str = "any of them",
                           description: str = "") -> str:
    strings_block = "\n        ".join(f'{k} = "{v}"' for k, v in strings.items())
    return YARA_TEMPLATE.format(
        rule_name=rule_name,
        description=description or rule_name,
        strings_block=strings_block,
        condition=condition,
    )
