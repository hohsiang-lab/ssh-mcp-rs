#!/usr/bin/env python3
"""Real SSH + MCP smoke tests; isolated keys/sshd and temporary files only.
Requires Unix, python3, ssh-keygen, sshd, git and gh. No GitHub token is used.
Run as a user supported by the local sshd (CI runs inside an ephemeral container).
"""
import argparse
import pwd
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(f"test process exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("test process did not listen")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class Client:
    def __init__(self, binary, config, log):
        self.process = subprocess.Popen(
            [str(binary), "--config", str(config)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        self.sequence = 0
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        result = self.request("initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "integration-no-elicitation", "version": "1"}})
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "ssh-mcp-rs"
        assert result["serverInfo"]["version"] == "0.1.0"
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        request_id = self.sequence
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id,
                                             "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not self.selector.select(timeout=max(0, deadline - time.monotonic())):
                break
            line = self.process.stdout.readline()
            if not line:
                raise AssertionError("MCP server unexpectedly closed stdout")
            value = json.loads(line)
            if "method" in value:
                assert "id" not in value, f"unexpected server request: {value['method']}"
                continue
            assert value.get("id") == request_id, value
            assert "error" not in value, value
            return value["result"]
        raise AssertionError("MCP response timed out")

    def call(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        self.selector.close()
        self.process.stdin.close()
        stop(self.process)


def data(result):
    assert not result.get("isError"), result
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def rejected(result, expected):
    assert result.get("isError"), result
    assert expected in str(result), result


def http(port, payload=None, token=None, origin=None, host=None, path="/mcp"):
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-11-25"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if origin:
        headers["Origin"] = origin
    if host:
        headers["Host"] = host
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/ssh-mcp-rs")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    for executable in ("ssh-keygen", "sshd", "git", "gh"):
        assert shutil.which(executable), f"missing test prerequisite: {executable}"
    assert binary.is_file(), "build the binary before running integration tests"
    checks = []
    with tempfile.TemporaryDirectory(prefix=".ssh-mcp-rs-test-", dir=Path(pwd.getpwuid(os.getuid()).pw_dir)) as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        for name in ("client", "host"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        pin = subprocess.check_output(["ssh-keygen", "-lf", str(root / "host.pub"), "-E", "sha256"], text=True).split()[1]
        port = unused_port()
        sshd_config = root / "sshd_config"
        sshd_config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {root}/host\n"
            f"PidFile {root}/sshd.pid\nAuthorizedKeysFile {root}/client.pub\n"
            "StrictModes yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "UsePAM no\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\n"
            "AllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\n"
            f"AllowUsers {pwd.getpwuid(os.getuid()).pw_name}\nSubsystem sftp internal-sftp\n")
        config = root / "config.toml"
        text = f'''[defaults]
defaultProfile = "read"
commandTimeoutMs = 1000
commandMaxOutputBytes = 128
transferMaxBytes = 1024
auditPath = "{root}/audit.jsonl"
'''
        for name, readonly, policy, fingerprint in (
            ("read", True, "deny", pin), ("dev", False, "client-confirmation", pin),
            ("denied", False, "deny", pin), ("badhost", False, "client-confirmation", "SHA256:" + "A" * 43)):
            text += f'''\n[[profiles]]
name = "{name}"
host = "127.0.0.1"
port = {port}
user = "{pwd.getpwuid(os.getuid()).pw_name}"
keyRef = "{root}/client"
hostKeySha256 = "{fingerprint}"
readOnly = {str(readonly).lower()}
approvalPolicy = "{policy}"
'''
        config.write_text(text)
        config.chmod(0o600)
        subprocess.run([str(binary), "--config", str(config), "--check-config"], check=True)
        with (root / "sshd.log").open("w+") as ssh_log, (root / "server.log").open("w+") as server_log:
            sshd = subprocess.Popen([shutil.which("sshd"), "-D", "-e", "-f", str(sshd_config)], stdout=ssh_log, stderr=ssh_log)
            client = None
            server = None
            try:
                wait_port(port, sshd)
                client = Client(binary, config, server_log)
                tools = client.request("tools/list", {})["tools"]
                assert len(tools) == 10
                for tool in tools:
                    write = tool["name"] in ("run_command", "sftp_upload", "open_session", "close_session", "signal_process")
                    assert tool["annotations"]["readOnlyHint"] is not write
                    assert tool["annotations"]["destructiveHint"] is write
                checks.append("MCP initialize/tools and truthful write annotations")
                assert len(data(client.call("list_connections", {}))["profiles"]) == 4
                for command in ("uname -a", "id", "git --version", "gh --version"):
                    output = data(client.call("read_command", {"command": command}))
                    assert output["exitStatus"] == 0, output
                checks.append("real SSH: uname/id/git/gh version queries")
                for command in ("id; touch /tmp/no", "git status", "gh api --method POST /test"):
                    rejected(client.call("read_command", {"command": command}), "READ_ONLY_DENIED")
                checks.append("read grammar denies shell injection and mutable git/gh")
                destination = root / "payload.txt"
                for profile in ("read", "denied"):
                    rejected(client.call("run_command", {"profile": profile, "command": "touch " + str(destination)}), "POLICY_DENIED")
                    rejected(client.call("sftp_upload", {"profile": profile, "remotePath": str(destination), "content": "denied"}), "POLICY_DENIED")
                    assert not destination.exists()
                checks.append("read-only and deny profiles refuse writes before effects")
                rejected(client.call("run_command", {"profile": "badhost", "command": "id"}), "HOST_KEY_MISMATCH")
                checks.append("incorrect host key is refused")
                assert data(client.call("run_command", {"profile": "dev", "cwd": str(root), "command": "printf hello > command.txt"}))["ok"]
                assert (root / "command.txt").read_text() == "hello"
                checks.append("write-enabled command with cwd and no elicitation capability")
                data(client.call("sftp_upload", {"profile": "dev", "remotePath": str(destination), "content": "first"}))
                assert destination.read_text() == "first"
                assert destination.stat().st_mode & 0o777 == 0o600
                rejected(client.call("sftp_upload", {"profile": "dev", "remotePath": str(destination), "content": "second"}), "")
                assert destination.read_text() == "first"
                data(client.call("sftp_upload", {"profile": "dev", "remotePath": str(destination), "content": "second", "overwrite": True}))
                assert data(client.call("sftp_download", {"remotePath": str(destination)}))["content"] == "second"
                checks.append("SFTP 0600 create/download and explicit overwrite")
                rejected(client.call("sftp_upload", {"profile": "dev", "remotePath": str(root / "large"), "content": "x" * 1025}), "TRANSFER_TOO_LARGE")
                (root / "large").write_text("x" * 1025)
                rejected(client.call("sftp_download", {"remotePath": str(root / "large")}), "TRANSFER_TOO_LARGE")
                checks.append("upload and download limits")
                command = "git init -q work && git init -q --bare remote.git && cd work && git config user.name Test && git config user.email test@example.invalid && printf test > README && git add README && git commit -qm test && git push -q ../remote.git HEAD:main"
                assert data(client.call("run_command", {"profile": "dev", "cwd": str(root), "command": command}))["ok"]
                assert subprocess.check_output(["git", "--git-dir", str(root / "remote.git"), "show", "main:README"], text=True) == "test"
                checks.append("real Git init/add/commit/push to isolated bare repository")
                # Persistent shell, background streaming and controlled process termination.
                rejected(client.call("open_session", {"profile":"read", "name":"blocked", "type":"interactive"}), "POLICY_DENIED")
                rejected(client.call("signal_process", {"profile":"read", "pid":23456, "signal":"TERM"}), "POLICY_DENIED")
                data(client.call("open_session", {"profile":"dev", "name":"interactive-test", "type":"interactive"}))
                assert data(client.call("run_command", {"profile":"dev", "session":"interactive-test", "command":"cd " + str(root)}))["ok"]
                assert data(client.call("run_command", {"profile":"dev", "session":"interactive-test", "command":"export MCP_SAVED=kept"}))["ok"]
                result = data(client.call("run_command", {"profile":"dev", "session":"interactive-test", "command":"pwd; printf ':%s' \"$MCP_SAVED\""}))
                assert str(root) in result["stdout"] and ":kept" in result["stdout"], result
                assert "interactive-test" in str(data(client.call("list_sessions", {})))
                rejected(client.call("read_session_output", {"profile":"dev", "name":"interactive-test"}), "background")
                data(client.call("close_session", {"profile":"dev", "name":"interactive-test"}))
                data(client.call("open_session", {"profile":"dev", "name":"background-test", "type":"background", "command":"printf 'before\\n'; sleep 1; printf 'after\\n'"}))
                response = None
                for _ in range(30):
                    response = data(client.call("read_session_output", {"profile":"dev", "name":"background-test"}))
                    if not response["running"]:
                        break
                    time.sleep(0.1)
                assert response is not None and "before" in response["stdout"] and "after" in response["stdout"], response
                assert response["exitStatus"] == 0, response
                data(client.call("close_session", {"profile":"dev", "name":"background-test"}))
                child = subprocess.Popen(["sleep", "30"])
                try:
                    result = data(client.call("signal_process", {"profile":"dev", "pid": child.pid, "signal":"TERM"}))
                    assert result["ok"], result
                    assert child.wait(timeout=5) != 0
                finally:
                    stop(child)
                rejected(client.call("signal_process", {"profile":"dev", "pid":1, "signal":"KILL"}), "invalid pid")
                checks.append("persistent interactive shell, background lifecycle, signal and read-only guards")
                nonzero = client.call("run_command", {"profile": "dev", "command": "printf error >&2; exit 7"})
                assert nonzero["isError"] and nonzero["structuredContent"]["exitStatus"] == 7
                checks.append("nonzero exit is an MCP tool error")
                output = data(client.call("run_command", {"profile": "dev", "command": "printf '%1000s' x"}))
                assert output["truncated"] and len(output["stdout"]) <= 128
                timeout = client.call("run_command", {"profile": "dev", "command": "sleep 2"})
                assert timeout["isError"] and timeout["structuredContent"]["timedOut"]
                assert timeout["structuredContent"]["remoteProcessMayContinue"]
                checks.append("bounded output and honest timeout/remote-process reporting")
                client.close()
                client = None
                http_port = unused_port()
                token = secrets.token_hex(32)
                server = subprocess.Popen([str(binary), "--config", str(config), "--transport", "http", "--bind", f"127.0.0.1:{http_port}"],
                    env={**os.environ, "SSH_MCP_HTTP_TOKEN": token}, stdout=server_log, stderr=server_log)
                wait_port(http_port, server)
                assert http(http_port, path="/health")[0] == 200
                assert http(http_port)[0] == 401
                assert http(http_port, token="wrong")[0] == 401
                assert http(http_port, token=token, origin="https://untrusted.invalid")[0] == 403
                request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "http-integration", "version": "1"}}}
                status, body = http(http_port, request, token)
                assert status == 200 and "result" in json.loads(body), (status, body)
                status, body = http(http_port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, token)
                assert status == 200 and len(json.loads(body)["result"]["tools"]) == 10, (status, body)
                status, body = http(http_port, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                    "name": "run_command", "arguments": {"profile": "dev", "command": "printf http-ok"}}}, token)
                assert status == 200 and data(json.loads(body)["result"])["stdout"] == "http-ok", (status, body)
                assert http(http_port, request, token, host="untrusted.invalid")[0] in (400, 403)
                checks.append("Streamable HTTP handshake/tools/call, bearer auth, Origin and Host rejection")
                stop(server)
                server = None
                audit = (root / "audit.jsonl").read_text()
                assert "printf hello" not in audit and token not in audit
                events = [json.loads(line) for line in audit.splitlines()]
                assert all(event["approvalEvidence"] == "not-attested" for event in events)
                assert any(event["phase"] == "failed" for event in events)
                checks.append("audit records omit command/content secrets and do not fabricate approval")
            except Exception:
                ssh_log.flush(); server_log.flush()
                print("TEST SSH LOG:", (root / "sshd.log").read_text()[-5000:])
                print("TEST MCP LOG:", (root / "server.log").read_text()[-5000:])
                raise
            finally:
                if client:
                    client.close()
                if server:
                    stop(server)
                stop(sshd)
    for check in checks:
        print("PASS:", check)
    print(f"{len(checks)} integration checks passed; temporary keys, processes and files removed")


if __name__ == "__main__":
    main()
