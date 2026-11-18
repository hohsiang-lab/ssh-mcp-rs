# Native Rust upstream command classifier

The SSH MCP binary runs a native Rust port of the command classification and hard-denial logic
from [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp) v2.26.0,
pinned at `e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f`.

- Runtime: **Pure Rust**. No JavaScript, Node.js, QuickJS or embedded script evaluator.
- The 68 reader grammars and 29 interpreter descriptions are compiled in as declarative JSON
  (`src/upstream_reader_data.json`, `src/upstream_interpreter_data.json`).
- Native source: `src/upstream_native.rs` and the `src/upstream_*.rs` helpers.
- Parity: `tests/upstream_classifier_oracle.json` records 5,991 original upstream
  classification + hard-denial outcomes. `tests/native_security_regressions.json`
  adds 1,273 additional upstream outcomes covering shell carriers, privilege wrappers,
  AWK, interpreters, remote writes, Windows names, and dangerous commands.
  A further 363 encoded PowerShell cases in `tests/native_powershell_regressions.json`
  protect Base64 decoder compatibility (URL-safe characters, ignored invalid bytes,
  omitted padding).
- Both datasets are asserted directly against the native Rust implementation in
  `cargo test --all-targets --locked`.

The source material is MIT licensed. Preserve `licenses/ssh-mcp-upstream-LICENSE`,
`NOTICE` and the attribution in README when updating rules. Upstream updates require
reviewing changes to the TypeScript originals, updating the Rust implementation and
pinned data, regenerating characterization fixtures independently and passing all tests.

The `safe` class is not a guarantee of no side effects: write operations still
require profile write permission and client-managed confirmation. Hard denials cannot
be overridden by approvals.
