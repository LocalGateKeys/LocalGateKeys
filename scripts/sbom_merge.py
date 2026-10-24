"""Add the non-Python release components to a CycloneDX SBOM.

``cyclonedx-py environment`` describes the Python packages that end up inside
the frozen executables.  Two further kinds of shipped code are invisible to it:

* the two vendored OpenCV Zoo ONNX face models (hash-pinned by
  ``release-inputs/face-models.manifest.json`` and ``localvault.face_models``);
* the Chromium browser extension, which is installed verbatim from
  ``browser-extension/``.

This helper appends one component per model and one for the extension (with a
per-file hash list and a canonical aggregate SHA-256), links them to the root
component in ``dependencies``, and writes the merged document.  It is pure
standard library so the build does not grow another dependency.

Usage::

    python scripts/sbom_merge.py --sbom env.cdx.json --output release.cdx.json \
        --model-manifest release-inputs/face-models.manifest.json \
        --extension-dir browser-extension
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

MODEL_UPSTREAM = "https://github.com/opencv/opencv_zoo"
# SPDX identifiers from the upstream opencv_zoo model directories.
MODEL_LICENSES = {
    "face_detection_yunet": "MIT",
    "face_recognition_sface": "Apache-2.0",
}
_VERSION_TOKEN = re.compile(r"_(\d{4}[a-z]{3})(?:_|\.|$)")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_components(manifest_path: Path) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    models = manifest.get("models")
    if manifest.get("schema") != 1 or not isinstance(models, list) or not models:
        raise SystemExit(f"Unsupported face-model manifest: {manifest_path}")
    components: list[dict[str, Any]] = []
    for model in sorted(models, key=lambda row: str(row.get("name", ""))):
        name = str(model["name"])
        digest = str(model["sha256"]).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SystemExit(f"Model {name} has a malformed SHA-256 in {manifest_path}")
        match = _VERSION_TOKEN.search(name)
        family = next((key for key in MODEL_LICENSES if name.startswith(key)), None)
        component: dict[str, Any] = {
            "type": "machine-learning-model",
            "bom-ref": f"model:{name}",
            "name": name,
            "version": match.group(1) if match else "unknown",
            "description": (
                "Vendored OpenCV Zoo ONNX model used only by the optional local webcam "
                "verification route; hash-verified at build time and never downloaded "
                "by the installed application."
            ),
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "externalReferences": [{"type": "distribution", "url": MODEL_UPSTREAM}],
            "properties": [
                {"name": "localgatekeys:size-bytes", "value": str(int(model.get("size", 0)))},
                {
                    "name": "localgatekeys:packaged-in",
                    "value": "LocalGateKeys.exe payload (localvault/models)",
                },
            ],
        }
        if family:
            component["licenses"] = [{"license": {"id": MODEL_LICENSES[family]}}]
        components.append(component)
    return components


def _extension_component(extension_dir: Path) -> dict[str, Any]:
    manifest_path = extension_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = sorted(
        (
            path for path in extension_dir.rglob("*")
            if path.is_file() and not path.name.startswith(".")
        ),
        key=lambda path: path.relative_to(extension_dir).as_posix(),
    )
    if not files:
        raise SystemExit(f"Browser extension directory is empty: {extension_dir}")
    aggregate = hashlib.sha256()
    properties: list[dict[str, str]] = []
    for path in files:
        relative = path.relative_to(extension_dir).as_posix()
        digest = _sha256_file(path)
        aggregate.update(f"{relative}\0{digest}\n".encode())
        properties.append({"name": f"localgatekeys:file:{relative}", "value": digest})
    return {
        "type": "application",
        "bom-ref": "extension:localgatekeys-browser-extension",
        "name": str(manifest.get("name", "LocalGateKeys browser extension")),
        "version": str(manifest.get("version", "0")),
        "description": (
            "Chromium Manifest V3 extension installed verbatim from browser-extension/. "
            "The SHA-256 is computed over the sorted list of 'relative-path NUL sha256' "
            "lines of every file, so it changes when any file changes."
        ),
        "hashes": [{"alg": "SHA-256", "content": aggregate.hexdigest()}],
        "properties": [
            {
                "name": "localgatekeys:manifest-version",
                "value": str(manifest.get("manifest_version", "")),
            },
            {"name": "localgatekeys:file-count", "value": str(len(files))},
            *properties,
        ],
    }


def merge(sbom: dict[str, Any], extra: list[dict[str, Any]]) -> dict[str, Any]:
    components = sbom.setdefault("components", [])
    existing = {component.get("bom-ref") for component in components}
    for component in extra:
        if component["bom-ref"] in existing:
            raise SystemExit(f"Duplicate bom-ref in SBOM: {component['bom-ref']}")
        components.append(component)
    root_ref = (sbom.get("metadata") or {}).get("component", {}).get("bom-ref")
    if root_ref:
        dependencies = sbom.setdefault("dependencies", [])
        root = next((entry for entry in dependencies if entry.get("ref") == root_ref), None)
        if root is None:
            root = {"ref": root_ref, "dependsOn": []}
            dependencies.append(root)
        depends_on = root.setdefault("dependsOn", [])
        for component in extra:
            if component["bom-ref"] not in depends_on:
                depends_on.append(component["bom-ref"])
        for component in extra:
            if not any(entry.get("ref") == component["bom-ref"] for entry in dependencies):
                dependencies.append({"ref": component["bom-ref"], "dependsOn": []})
    return sbom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--sbom", required=True, type=Path, help="CycloneDX JSON from cyclonedx-py"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-manifest", required=True, type=Path)
    parser.add_argument("--extension-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    if sbom.get("bomFormat") != "CycloneDX":
        raise SystemExit(f"{args.sbom} is not a CycloneDX JSON document")
    extra = [*_model_components(args.model_manifest), _extension_component(args.extension_dir)]
    merged = merge(sbom, extra)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_name(args.output.name + ".tmp")
    temp.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(args.output)
    print(
        f"SBOM components: {len(merged['components'])} "
        f"({len(extra)} non-Python) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
