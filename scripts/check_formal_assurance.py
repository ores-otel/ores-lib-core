#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "formal" / "redaction-assurance.v1.json"
SCHEMA_PATH = ROOT / "formal" / "redaction-assurance.schema.json"
EXPECTED_PROPERTIES = {
    "idempotence",
    "sensitive-value-noninterference",
    "safe-field-preservation",
    "normalization-closure",
    "secret-representation-opacity",
}
EXPECTED_LANGUAGES = {"typescript", "rust", "dart"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path} must contain an object")
    return value


def main() -> int:
    schema = load_json(SCHEMA_PATH)
    manifest = load_json(MANIFEST_PATH)

    require(
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
        "assurance schema must use JSON Schema 2020-12",
    )
    require(schema.get("additionalProperties") is False, "assurance schema must be closed")
    require(
        manifest.get("$schema") == "./redaction-assurance.schema.json",
        "manifest schema reference drifted",
    )
    require(
        manifest.get("schema") == "ores-lib-core/redaction-assurance/v1",
        "manifest identity drifted",
    )
    require(manifest.get("subject") == "credential-redaction", "subject drifted")
    require(manifest.get("criticality") == "security", "criticality must remain security")

    properties = manifest.get("properties")
    require(isinstance(properties, list), "properties must be a list")
    require(set(properties) == EXPECTED_PROPERTIES, "formal property set is incomplete")
    require(len(properties) == len(set(properties)), "formal properties must be unique")

    domain = manifest.get("domain")
    require(isinstance(domain, dict), "domain must be an object")
    roots = domain.get("sensitiveRoots")
    safe_fields = domain.get("safeFields")
    prefixes = domain.get("prefixes")
    require(isinstance(roots, list) and roots, "sensitive roots are required")
    require(len(roots) == len(set(roots)), "sensitive roots must be unique")
    require(isinstance(safe_fields, list) and safe_fields, "safe fields are required")
    require(isinstance(prefixes, list) and prefixes, "prefixes are required")

    refinements = manifest.get("refinements")
    require(isinstance(refinements, dict), "refinements must be an object")
    require(set(refinements) == EXPECTED_LANGUAGES, "Rust, Dart, and TypeScript are required")
    for language, refinement in refinements.items():
        require(isinstance(refinement, dict), f"{language} refinement must be an object")
        require(set(refinement) == {"source", "check"}, f"{language} refinement must be closed")
        source_path = ROOT / str(refinement["source"])
        check_path = ROOT / str(refinement["check"])
        require(source_path.is_file(), f"missing {language} source: {source_path}")
        require(check_path.is_file(), f"missing {language} formal check: {check_path}")
        source = source_path.read_text(encoding="utf-8")
        for root in roots:
            require(str(root) in source, f"{language} is missing sensitive root {root}")

    print(
        "formal redaction assurance valid: "
        f"properties={len(properties)} roots={len(roots)} languages={len(refinements)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
