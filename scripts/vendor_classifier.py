#!/usr/bin/env python3
"""Bundle a built, pinned tufantunc/ssh-mcp classifier into the Rust binary.

Usage: checkout the exact upstream commit, run npm ci && npm run build there,
then run python3 scripts/vendor_classifier.py /path/to/upstream-checkout.
"""
from pathlib import Path
import subprocess
import sys

PIN = "e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f"
PARTS = ("remote-path", "never-allowed-writes", "awk", "reader-grammar", "classifier")

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: vendor_classifier.py <built-upstream-checkout>")
    upstream = Path(sys.argv[1]).resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != PIN:
        raise SystemExit(f"Expected pinned commit {PIN}, got {revision}")
    segments = []
    for part in PARTS:
        code = (upstream / "build/policy" / (part + ".js")).read_text()
        code = "\n".join(
            line for line in code.splitlines()
            if not (line.startswith("import ") or line.startswith("export {"))
        )
        code = code.replace("export function ", "function ")
        code = code.replace("export const ", "const ")
        code = code.replace("export class ", "class ")
        segments.append("// --- upstream " + part + ".ts ---\n" + code)
    header = (
        "/*\n"
        " * Vendored tufantunc/ssh-mcp classifier, commit " + PIN + ".\n"
        " * Original authors, MIT License (see licenses/ssh-mcp-upstream-LICENSE).\n"
        " * Generated from upstream TypeScript build; do not edit manually.\n"
        " */\nvar UpstreamSSH = (function() {\n"
    )
    output = header + "\n".join(segments) + "\nreturn {classifyCommand, findForbiddenMatch};\n})();\n"
    root = Path(__file__).resolve().parent.parent
    destination = root / "src/upstream_classifier.js"
    destination.write_text(output)
    (root / "licenses").mkdir(exist_ok=True)
    (root / "licenses/ssh-mcp-upstream-LICENSE").write_bytes(
        (upstream / "LICENSE").read_bytes()
    )
    print(f"Bundled pinned upstream to {destination} ({len(output)} bytes)")

if __name__ == "__main__":
    main()
