# Prebuilt binaries and releases

Users can install a published archive from [GitHub Releases](https://github.com/hohsiang-lab/ssh-mcp-rs/releases) without cloning the repository, installing Rust, or compiling the server. A release must have been published first; adding the workflow alone does not publish a version.

## Available build targets

| Machine | Archive target | Standard GitHub runner |
| --- | --- | --- |
| Linux x86_64 / amd64 | `x86_64-unknown-linux-gnu` | `ubuntu-22.04` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` |
| macOS Intel | `x86_64-apple-darwin` | `macos-15-intel` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `macos-15` |

These are standard **GitHub-provided runners**, not self-hosted/Monster runners or paid larger-runner labels. See the [official runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Linux GNU archives are built on Ubuntu 22.04. Use glibc 2.35 or newer; these are not static musl/Alpine binaries. macOS packages are smoke-tested on macOS 15, not on older OS versions. No Windows binary is provided because the implementation requires Unix. macOS assets are not Developer ID signed or notarized; follow your organization's software approval policy.

Archives are named `ssh-mcp-rs-v<version>-<target>.tar.gz` and contain the executable, README, configuration example, documentation, LICENSE, and NOTICE. The release also includes `SHA256SUMS` for all four archives. Checksums detect corruption; they are not an independent signature or provenance attestation.

## Download and install

Choose an existing release tag and the target for your machine. This example uses Linux amd64 and version `v0.2.0`; change them to a version actually listed in Releases. No authentication is needed to download public release assets.

Run in a new, empty directory, using a POSIX shell such as bash or zsh:

```sh
set -eu
version=v0.2.0
target=x86_64-unknown-linux-gnu
package="ssh-mcp-rs-${version}-${target}"
archive="${package}.tar.gz"
base="https://github.com/hohsiang-lab/ssh-mcp-rs/releases/download/${version}"

curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" "$base/$archive"
curl --fail --location --proto '=https' --tlsv1.2 --output SHA256SUMS "$base/SHA256SUMS"
awk -v asset="$archive" '$2 == asset { print }' SHA256SUMS > selected.sha256
test "$(wc -l < selected.sha256 | tr -d ' ')" = 1
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --check selected.sha256
else
  shasum -a 256 --check selected.sha256
fi

tar -xzf "$archive"
"./$package/ssh-mcp-rs" --version
mkdir -p "$HOME/.local/bin"
install -m 755 "$package/ssh-mcp-rs" "$HOME/.local/bin/ssh-mcp-rs"
```

For an Apple Silicon Mac, set `target=aarch64-apple-darwin`. Add `$HOME/.local/bin` to PATH or use the full executable path in your MCP/tunnel configuration. Do not pipe a downloaded install script into a shell.

For a **new installation**, copy the included configuration example to a private directory without overwriting an existing configuration:

```sh
umask 077
mkdir -p "$HOME/.config/ssh-mcp-rs"
chmod 700 "$HOME/.config/ssh-mcp-rs"
config="$HOME/.config/ssh-mcp-rs/config.toml"
if test -e "$config" || test -L "$config"; then
  printf '%s\n' 'Existing config preserved; review it separately.'
else
  cp "$package/config.example.toml" "$config"
  chmod 600 "$config"
fi
```

Edit the SSH account, key path, and **independently verified** host fingerprint. Then run:

```sh
"$HOME/.local/bin/ssh-mcp-rs" --config "$config" --check-config
```

A prebuilt executable removes only the build requirement. SSH credentials, host verification, client-managed confirmation, and the authenticated MCP transport still need configuration. Git/gh must be installed and authorized on the remote SSH host when those commands are used. Updating a binary does not restart a service or migrate existing configuration automatically.

## Publish a version (maintainers)

Merge the release workflow and reviewed source changes into `main`. The package version in `Cargo.toml` and its root `Cargo.lock` entry must match. Create a version tag on the reviewed main-branch commit, for example:

```sh
git switch main
git pull --ff-only
git tag -a v0.2.0 -m 'ssh-mcp-rs v0.2.0'
git push origin v0.2.0
```

The workflow then:

1. Checks that the tag equals `v` plus the manifest version and that its commit belongs to `main`.
2. Runs the existing Linux unit/lint/SSH-MCP integration suite on that exact source and builds all four release binaries with `--locked`.
3. Extracts every archive and checks its executable's version and help on its native runner.
4. Collects all four archives, verifies their SHA256 checksums, and checks that the tag still identifies the built commit.
5. Publishes the GitHub Release and checksum file using the workflow's short-lived `GITHUB_TOKEN`. A tag containing a prerelease suffix produces a prerelease.

Only the publish job has `contents: write`. Existing releases are refused rather than overwritten. A failed build or check prevents publication. No personal token or separate release service is required.

Pull requests that change release/build inputs run the four build/package jobs and upload temporary Actions artifacts, but **never publish a release**. Manual `workflow_dispatch` is also a build-only rehearsal. Artifacts expire after seven days; published Release assets are separate. Trigger a real version release only by pushing its matching `v*` tag.
