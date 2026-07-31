#!/usr/bin/env python3
"""Non-destructive cross-UID Drive/XLSX release smoke.

Run this as the enrolled Hermes account. It creates a uniquely named Drive
folder, uploads and downloads a small XLSX through the UID-authenticated local
data plane, verifies bytes and workbook readability, then permanently deletes
only the two artifacts it created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection", default="drive")
    parser.add_argument("--agentsso", default="agentsso")
    return parser.parse_args()


class McpBridge:
    def __init__(self, agentsso: str) -> None:
        self._next_id = 1
        self._process = subprocess.Popen(
            [agentsso, "mcp", "bridge", "--service", "drive"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "permitlayer-release-smoke", "version": "1"},
            },
        )
        self.notify("notifications/initialized", {})

    def request(self, method: str, params: dict) -> dict:
        request_id = self._next_id
        self._next_id += 1
        self._write(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        assert self._process.stdout is not None
        while True:
            line = self._process.stdout.readline()
            if not line:
                assert self._process.stderr is not None
                error = self._process.stderr.read().strip()
                raise RuntimeError(f"MCP bridge closed unexpectedly: {error}")
            response = json.loads(line)
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise RuntimeError(f"MCP {method} failed: {response['error']}")
            return response["result"]

    def notify(self, method: str, params: dict) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def tool(self, name: str, arguments: dict) -> str:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"MCP tool {name} failed: {result}")
        blocks = result.get("content", [])
        return "".join(block.get("text", "") for block in blocks if block.get("type") == "text")

    def _write(self, value: dict) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self._process.stdin.flush()

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    return json.loads(completed.stdout)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    args = parse_args()
    if os.geteuid() < 501:
        raise RuntimeError("run this smoke as the enrolled non-system Hermes user")
    try:
        import openpyxl
    except ImportError as error:
        raise RuntimeError("openpyxl is required for workbook readability verification") from error

    marker = f"permitlayer-smoke-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    bridge = McpBridge(args.agentsso)
    folder_id: str | None = None
    file_id: str | None = None
    cleanup_errors: list[str] = []
    try:
        folder = json.loads(
            bridge.tool(
                "drive.files.create",
                {
                    "file": {
                        "name": marker,
                        "mimeType": "application/vnd.google-apps.folder",
                    },
                    "fields": "id,name",
                },
            )
        )
        folder_id = folder["id"]
        with tempfile.TemporaryDirectory(prefix="permitlayer-xlsx-smoke-") as directory:
            root = pathlib.Path(directory)
            source = root / "source.xlsx"
            downloaded = root / "downloaded.xlsx"
            workbook = openpyxl.Workbook()
            workbook.active["A1"] = marker
            workbook.save(source)

            uploaded = run_json(
                [
                    args.agentsso,
                    "drive",
                    "upload",
                    str(source),
                    "--connection",
                    args.connection,
                    "--parent",
                    folder_id,
                    "--json",
                ]
            )
            file_id = uploaded["file"]["id"]
            run_json(
                [
                    args.agentsso,
                    "drive",
                    "download",
                    file_id,
                    "--connection",
                    args.connection,
                    "--output",
                    str(downloaded),
                    "--json",
                ]
            )
            if sha256(source) != sha256(downloaded):
                raise RuntimeError("XLSX round-trip SHA-256 mismatch")
            loaded = openpyxl.load_workbook(downloaded, read_only=True, data_only=False)
            if loaded.active["A1"].value != marker:
                raise RuntimeError("downloaded workbook sentinel mismatch")
            loaded.close()
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "folder_id": folder_id,
                        "file_id": file_id,
                        "sha256": sha256(downloaded),
                    },
                    separators=(",", ":"),
                )
            )
    finally:
        for artifact_id in [file_id, folder_id]:
            if artifact_id is None:
                continue
            try:
                bridge.tool("drive.files.delete", {"file_id": artifact_id})
            except Exception as error:  # cleanup must try both exact artifacts
                cleanup_errors.append(f"{artifact_id}: {error}")
        bridge.close()
        if cleanup_errors:
            print(
                f"cleanup failed for smoke artifacts named {marker}: "
                + "; ".join(cleanup_errors),
                file=sys.stderr,
            )
    return 0 if not cleanup_errors else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
