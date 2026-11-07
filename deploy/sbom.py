#!/usr/bin/env python3
"""Write a CycloneDX 1.5 SBOM (JSON) of the Python environment that runs this script.

The container build runs it with the image's own interpreter after installing the hash-pinned
dependencies (deploy/locks/*.txt), so the SBOM lists exactly what the image contains:

    /opt/axentra/bin/python -I deploy/sbom.py --component axentra > /opt/axentra/sbom.cdx.json

Standard library only. The output is deterministic for the same set of installed distributions:
components are sorted, the serial number is derived from their content, and a timestamp is added
only when SOURCE_DATE_EPOCH is set (reproducible builds).
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from importlib import metadata
import json
import os
import re
import sys
from typing import Any
import uuid

SPEC_VERSION = "1.5"
TOOL_NAME = "axentra-sbom"
TOOL_VERSION = "1"
#: Distributions of the packaging toolchain itself, not of the application.
TOOLING = {"pip", "setuptools", "wheel"}


def normalize(name: str) -> str:
    """PEP 503 normalized name (as used in package URLs)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{normalize(name)}@{version}"


def licenses(meta: Any) -> list[dict[str, Any]]:
    expression = meta.get("License-Expression")
    if expression:
        return [{"expression": expression.strip()}]
    found: list[dict[str, Any]] = []
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License :: "):
            name = classifier.split(" :: ")[-1].strip()
            if name and {"license": {"name": name}} not in found:
                found.append({"license": {"name": name}})
    if found:
        return found
    text = (meta.get("License") or "").strip()
    # Some distributions put the whole license text here; keep only a short name.
    if text and "\n" not in text and len(text) <= 100:
        return [{"license": {"name": text}}]
    return []


def component(dist: metadata.Distribution) -> dict[str, Any]:
    meta = dist.metadata
    name, version = meta["Name"], dist.version
    entry: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl(name, version),
        "name": normalize(name),
        "version": version,
        "purl": purl(name, version),
    }
    lic = licenses(meta)
    if lic:
        entry["licenses"] = lic
    return entry


def build(main_component: str | None) -> dict[str, Any]:
    seen: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if not name or normalize(name) in TOOLING:
            continue
        seen.setdefault(normalize(name), dist)
    main = seen.pop(normalize(main_component), None) if main_component else None
    components = sorted((component(d) for d in seen.values()), key=lambda c: (c["name"], c["version"]))
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]}
        },
        "components": components,
    }
    if main is not None:
        top = component(main)
        top["type"] = "application"
        bom["metadata"]["component"] = top
        bom["dependencies"] = [{"ref": top["bom-ref"], "dependsOn": [c["bom-ref"] for c in components]}]
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        bom["metadata"]["timestamp"] = datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'axentra-sbom:' + digest)}"
    return bom


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--component", help="the application's distribution name (metadata.component)")
    args = parser.parse_args(argv)
    json.dump(build(args.component), sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
