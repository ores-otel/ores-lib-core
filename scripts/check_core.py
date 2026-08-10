#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
LANGUAGES = {"rust", "typescript", "go", "python", "dart", "java", "swift"}
FORBIDDEN = re.compile(r"(?i)(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})")

def main() -> int:
    deps=json.loads((ROOT/"contracts/dependencies.json").read_text())
    packages={entry["package"] for entry in deps["dependencies"]}
    assert packages == {"ores-otel/ores-interfaces","oresoftware/next-loggers"}
    assert deps["globalProviderInstallationAllowed"] is False
    assert deps["rawBiometricMaterialAllowed"] is False
    present={path.name for path in (ROOT/"languages").iterdir() if path.is_dir()}
    assert LANGUAGES <= present
    for path in ROOT.rglob("*"):
        if path.resolve() == pathlib.Path(__file__).resolve():
            continue
        if path.is_file() and path.stat().st_size < 2_000_000:
            text=path.read_text(encoding="utf-8", errors="ignore")
            if match:=FORBIDDEN.search(text): raise AssertionError(f"secret marker in {path}: {match.group(0)}")
    print(f"core valid: dependencies={len(packages)} languages={len(present)}")
    return 0
if __name__ == "__main__": raise SystemExit(main())
