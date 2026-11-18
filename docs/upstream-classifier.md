# Bundled upstream command classifier

The binary runs the original classifier and unconditional-denial checks from
[tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp), **v2.26.0**,
commit `e04ebf21dd44f18f00ea2e0794b49d57dfaf3c7f`.
The upstream code is MIT licensed; see
[its license](../licenses/ssh-mcp-upstream-LICENSE).

- Vendored code: `src/upstream_classifier.js` (compiled from the upstream
  `remote-path`, `never-allowed-writes`, `awk`, `reader-grammar`, and
  `classifier` modules).
- Runtime: `rquickjs` is compiled into the Rust binary; neither Node.js
  nor network access is needed at runtime. QuickJS has a 32 MiB memory
  limit, 512 KiB stack, and a 2 second per-command deadline.
- Differential oracle: `tests/upstream_classifier_oracle.json`, generated
  by the original upstream implementation against its differential corpus.
  CI asserts **5,991** classification **and forbidden-result** matches.

## Updating the pinned classifier

Checkout the pinned upstream commit and run `npm ci && npm run build` in
that clone. Then run `python3 scripts/vendor_classifier.py /path/to/ssh-mcp`
from this repository. For a newer upstream revision, explicitly update the
script's pinned commit and regenerate the corresponding differential oracle.
Include a passing corpus comparison in the same PR.

The upstream `safe` class may include commands that change remote state.
Classification does **not** bypass the Rust profile write restriction,
the client-managed confirmation, or OS-level account permissions.
