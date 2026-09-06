#!/usr/bin/env python3
"""Run rooted Android acceptance checks for custom Frida server and Gadget builds."""

import argparse
import importlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if os.fspath(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(REPOSITORY_ROOT))
build: Any = importlib.import_module("build")

REMOTE_DIR = "/data/local/tmp/phantom-frida-test"
JAVA_BRIDGE_DIR = REPOSITORY_ROOT / "node_modules" / "frida-java-bridge"
PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
SCRIPT_TIMEOUT_SECONDS = 45
MEMORY_SCAN_MARKERS = (
    "frida:rpc",
    "FridaScriptEngine",
    "GLib-GIO",
    "GDBusProxy",
    "GumScript",
    "Frida/",
    "frida-agent",
    "frida-gadget",
    "frida-eternal-agent",
    "frida-generate-certificate",
    "frida-main-loop",
    "gum-js-loop",
    "pool-frida",
    "pool-spawner",
)
GADGET_PROBE_SOURCE = """'use strict';

rpc.exports = {
  add(left, right) {
    return left + right;
  }
};

send({ type: 'phantom-frida-gadget-result' });
"""


class SmokeFailure(RuntimeError):
    """A rooted-device acceptance failure."""


@dataclass(frozen=True)
class AndroidSmokeConfig:
    server: Path
    gadget: Path
    name: str
    port: int
    package: str
    ndk: Path


@dataclass(frozen=True)
class RemoteEndpoint:
    socket: str
    origin: str
    token: str


def create_remote_endpoint(name: str, role: str) -> RemoteEndpoint:
    nonce = secrets.token_hex(8)
    return RemoteEndpoint(
        socket=f"{name}-{role}-{nonce}",
        origin=f"https://{nonce}.invalid",
        token=secrets.token_urlsafe(24),
    )


def choose_gadget_port(server_port: int) -> int:
    candidate = server_port + 1
    return candidate if candidate <= 65535 and candidate != 27042 else 27043


def analyze_proc_maps(text: str) -> dict[str, int]:
    """Summarize executable mapping signals without retaining addresses or paths."""
    report = {
        "executable": 0,
        "rwx": 0,
        "anonymous_rwx": 0,
        "deleted_executable": 0,
        "memfd_executable": 0,
    }
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue
        permissions = fields[1]
        path = fields[5] if len(fields) == 6 else ""
        executable = len(permissions) >= 3 and permissions[2] == "x"
        if not executable:
            continue
        report["executable"] += 1
        if permissions.startswith("rwx"):
            report["rwx"] += 1
            if not path or path.startswith("["):
                report["anonymous_rwx"] += 1
        if "(deleted)" in path:
            report["deleted_executable"] += 1
        if path.startswith("/memfd:"):
            report["memfd_executable"] += 1
    return report


def analyze_thread_statuses(text: str) -> dict[str, object]:
    """Summarize per-thread tracer and blocked-signal state."""
    tracer_pids = [int(value) for value in re.findall(r"^TracerPid:\s*(\d+)$", text, re.MULTILINE)]
    signal_masks = re.findall(r"^SigBlk:\s*([0-9a-fA-F]+)$", text, re.MULTILINE)
    return {
        "threads": len(re.findall(r"^Name:\s*.+$", text, re.MULTILINE)),
        "nonzero_tracer": sum(pid != 0 for pid in tracer_pids),
        "sigblk": dict(Counter(signal_masks)),
    }


def assert_clean_proc_text(label: str, text: str) -> None:
    forbidden: tuple[str, ...] = (
        "frida-zymbiote",
        "frida-server",
        "frida-helper",
        "frida-gadget",
        "frida-eternal-agent",
        "frida-generate-certificate",
        "frida-main-loop",
    )
    if label == "threads":
        forbidden += (
            "gum-js-loop",
            "gmain",
            "gdbus",
            "pool-frida",
            "pool-spawner",
        )
    elif label == "fds":
        forbidden += ("linjector",)
    lowered = text.lower()
    matches = [marker for marker in forbidden if marker in lowered]
    if matches:
        raise SmokeFailure(f"{label} contains forbidden marker(s): {', '.join(matches)}")
    if label in {"status", "thread-status"} and re.search(
        r"^TracerPid:\s*[1-9]\d*$", text, re.MULTILINE
    ):
        raise SmokeFailure("status contains an active TracerPid")


def require_single_device(adb_output: str) -> str:
    devices = [
        fields[0]
        for line in adb_output.splitlines()[1:]
        if len(fields := line.split()) >= 2 and fields[1] == "device"
    ]
    if len(devices) != 1:
        raise SmokeFailure(f"Expected exactly one authorized adb device, found {len(devices)}")
    return devices[0]


def assert_interactive_device(power_state: str, window_policy: str) -> None:
    if "mWakefulness=Awake" not in power_state:
        raise SmokeFailure("Android device must be awake before spawn acceptance")
    if "mInputRestricted=false" not in window_policy:
        raise SmokeFailure("Android device must be unlocked before spawn acceptance")


def server_start_command(serial: str, remote_server: str, endpoint: RemoteEndpoint) -> list[str]:
    remote_log = f"{REMOTE_DIR}/server.log"
    return [
        "adb",
        "-s",
        serial,
        "shell",
        "su",
        "-c",
        (
            f"{remote_server} -l unix:{endpoint.socket} "
            f"--origin {endpoint.origin} --token {endpoint.token} "
            f"-D </dev/null >{remote_log} 2>&1"
        ),
    ]


def validate_config(
    *,
    server: Path,
    gadget: Path,
    name: str,
    port: int,
    package: str,
    ndk: Path,
) -> AndroidSmokeConfig:
    try:
        normalized_name = build.validate_custom_name(name)
        validated_port = build.validate_port(port)
    except RuntimeError as error:
        raise SmokeFailure(str(error)) from error

    if validated_port is None:
        raise SmokeFailure("A server port is required")
    if PACKAGE_PATTERN.fullmatch(package) is None:
        raise SmokeFailure(f"Invalid Android package: {package!r}")

    resolved_server = server.resolve()
    resolved_gadget = gadget.resolve()
    resolved_ndk = ndk.resolve()
    if not resolved_server.is_file():
        raise SmokeFailure(f"Server artifact is missing: {resolved_server}")
    if not resolved_gadget.is_file():
        raise SmokeFailure(f"Gadget artifact is missing: {resolved_gadget}")
    if not resolved_ndk.is_dir():
        raise SmokeFailure(f"Android NDK directory is missing: {resolved_ndk}")
    if resolved_server.suffix == ".gz" or resolved_gadget.suffix == ".gz":
        raise SmokeFailure("Pass uncompressed server and Gadget artifacts")

    return AndroidSmokeConfig(
        server=resolved_server,
        gadget=resolved_gadget,
        name=normalized_name,
        port=validated_port,
        package=package,
        ndk=resolved_ndk,
    )


def run_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    check: bool = True,
    redact: Sequence[str] = (),
) -> subprocess.CompletedProcess[str]:
    argv = [os.fspath(part) for part in command]
    displayed_argv = []
    for part in argv:
        displayed = part
        for secret in redact:
            if secret:
                displayed = displayed.replace(secret, "<redacted>")
        displayed_argv.append(displayed)
    print(f"+ {subprocess.list2cmdline(displayed_argv)}", flush=True)
    try:
        result = subprocess.run(argv, capture_output=True, text=True)
    except OSError as error:
        raise SmokeFailure(f"Unable to run {argv[0]}: {error}") from error
    if check and result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        for secret in redact:
            if secret:
                details = details.replace(secret, "<redacted>")
        suffix = f": {details}" if details else ""
        raise SmokeFailure(f"Command failed with exit code {result.returncode}: {argv[0]}{suffix}")
    return result


def adb(
    serial: str, *arguments: str | os.PathLike[str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return run_command(["adb", "-s", serial, *arguments], check=check, redact=(serial,))


def root_shell(
    serial: str, command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return adb(serial, "shell", "su", "-c", command, check=check)


def _load_build_metadata(config: AndroidSmokeConfig) -> dict[str, object]:
    metadata_path = config.server.parent / "build-info.json"
    if not metadata_path.is_file():
        raise SmokeFailure(f"build-info.json is required beside the server: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SmokeFailure(f"Invalid build metadata: {metadata_path}: {error}") from error
    if not isinstance(metadata, dict):
        raise SmokeFailure(f"Invalid build metadata: {metadata_path}: expected an object")
    return metadata


def _strict_wx_required(metadata: dict[str, object]) -> bool:
    value = metadata.get("strict_wx", False)
    if not isinstance(value, bool):
        raise SmokeFailure("build metadata strict_wx must be boolean")
    return value


def _load_matching_frida(config: AndroidSmokeConfig) -> ModuleType:
    metadata_path = config.server.parent / "build-info.json"
    metadata = _load_build_metadata(config)
    try:
        expected = str(metadata["frida_version"])
    except KeyError as error:
        raise SmokeFailure(f"Invalid build metadata: {metadata_path}: {error}") from error

    try:
        frida_module = importlib.import_module("frida")
    except ImportError as error:
        raise SmokeFailure(f"Install the matching Frida Python package ({expected})") from error
    actual = str(getattr(frida_module, "__version__", "unknown"))
    if actual != expected:
        raise SmokeFailure(f"Frida version mismatch: build requires {expected}, host has {actual}")
    return frida_module


def _compile_agent(frida_module: Any, script_path: Path) -> str:
    if not script_path.is_file():
        raise SmokeFailure(f"Frida acceptance script is missing: {script_path}")
    if not JAVA_BRIDGE_DIR.is_dir():
        raise SmokeFailure("frida-java-bridge is missing; run npm ci in the repository")

    diagnostics: list[str] = []
    compiler = frida_module.Compiler()
    compiler.on("diagnostics", lambda diagnostic: diagnostics.append(str(diagnostic)))
    try:
        bundle = compiler.build(
            os.fspath(script_path),
            project_root=os.fspath(REPOSITORY_ROOT),
        )
    except Exception as error:
        detail = f"; diagnostics: {' | '.join(diagnostics)}" if diagnostics else ""
        raise SmokeFailure(f"Could not bundle Frida acceptance agent: {error}{detail}") from error
    if not bundle:
        raise SmokeFailure("Frida compiler returned an empty acceptance agent")
    return str(bundle)


def _prepare_remote_files(config: AndroidSmokeConfig, serial: str) -> tuple[str, str]:
    remote_server = f"{REMOTE_DIR}/{config.name}-server"
    remote_gadget = f"{REMOTE_DIR}/lib{config.name}-gadget.so"
    adb(serial, "shell", "mkdir", "-p", REMOTE_DIR)
    adb(serial, "push", config.server, remote_server)
    adb(serial, "push", config.gadget, remote_gadget)
    adb(serial, "shell", "chmod", "755", remote_server)
    return remote_server, remote_gadget


def _configure_forward(serial: str, port: int, socket_name: str) -> None:
    adb(serial, "forward", "--remove", f"tcp:{port}", check=False)
    adb(serial, "forward", f"tcp:{port}", f"localabstract:{socket_name}")


def _wait_for_remote_device(
    manager: Any, address: str, endpoint: RemoteEndpoint, *, timeout: float = 20
) -> tuple[Any, list[Any]]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    device: Any = None
    while time.monotonic() < deadline:
        try:
            if device is None:
                device = manager.add_remote_device(
                    address,
                    origin=endpoint.origin,
                    token=endpoint.token,
                )
            return device, list(device.enumerate_processes())
        except Exception as error:  # external Frida exceptions vary by version
            last_error = error
            time.sleep(0.5)
    raise SmokeFailure(f"Frida endpoint {address} did not become ready: {last_error}")


def _run_script_acceptance(
    device: Any,
    serial: str,
    package: str,
    agent_source: str,
    memory_scanner: str,
    *,
    require_no_anonymous_rwx: bool = False,
) -> dict[str, object]:
    pid: int | None = None
    session: Any = None
    outcome: dict[str, Any] = {}
    completed = threading.Event()

    def on_message(message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "error":
            outcome["error"] = message.get("stack") or message.get("description") or message
            completed.set()
            return
        payload = message.get("payload")
        if (
            message.get("type") == "send"
            and isinstance(payload, dict)
            and payload.get("type") == "phantom-frida-result"
        ):
            outcome["payload"] = payload
            completed.set()

    try:
        pid = int(device.spawn([package]))
        session = device.attach(pid)
        script = session.create_script(agent_source)
        script.on("message", on_message)
        script.load()
        if script.exports_sync.add(20, 22) != 42:
            raise SmokeFailure("Stock Frida RPC returned an unexpected server result")
        device.resume(pid)

        if not completed.wait(SCRIPT_TIMEOUT_SECONDS):
            raise SmokeFailure(f"Frida script timed out after {SCRIPT_TIMEOUT_SECONDS} seconds")
        if "error" in outcome:
            raise SmokeFailure(f"Frida script error: {outcome['error']}")
        payload = outcome.get("payload")
        if not isinstance(payload, dict):
            raise SmokeFailure("Frida script returned no structured result")
        failures = payload.get("failures")
        if not isinstance(failures, list):
            raise SmokeFailure("Frida script result has no failures array")
        if failures:
            raise SmokeFailure(f"Frida script assertions failed: {failures}")
        if payload.get("javaAvailable") is not True:
            raise SmokeFailure("Java bridge is unavailable in the selected application")

        memory_report = _scan_process_procfs(
            serial,
            pid,
            memory_scanner,
            "memfd:jit-code-cache",
            require_no_anonymous_rwx=require_no_anonymous_rwx,
        )
        return {
            "pid": pid,
            "java_available": True,
            "script_failures": [],
            "memory": memory_report,
        }
    except SmokeFailure:
        raise
    except Exception as error:
        raise SmokeFailure(f"Frida server acceptance failed: {error}") from error
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass


def _parse_memory_scan(label: str, output: str) -> dict[str, int]:
    values: dict[str, int] = {}
    counts: dict[str, int] = {}
    for line in output.splitlines():
        if match := re.fullmatch(r"(ranges|executable)=(\d+)", line):
            values[match.group(1)] = int(match.group(2))
        elif match := re.fullmatch(r"marker=(.+) count=(\d+)", line):
            counts[match.group(1)] = int(match.group(2))

    if values.get("ranges", 0) == 0:
        raise SmokeFailure(f"{label} memory scan found no matching memory ranges")
    missing = [marker for marker in MEMORY_SCAN_MARKERS if marker not in counts]
    if missing:
        raise SmokeFailure(f"{label} memory scan omitted marker(s): {', '.join(missing)}")
    detected = [
        f"{marker}={counts[marker]}" for marker in MEMORY_SCAN_MARKERS if counts[marker] != 0
    ]
    if detected:
        raise SmokeFailure(f"{label} memory scan found runtime signature(s): {', '.join(detected)}")
    return {
        "ranges": values["ranges"],
        "executable": values.get("executable", 0),
    }


def _scan_process_procfs(
    serial: str,
    pid: int,
    memory_scanner: str,
    mapping_needle: str,
    *,
    require_no_anonymous_rwx: bool = False,
) -> dict[str, object]:
    commands = {
        "unix": "cat /proc/net/unix",
        "maps": f"cat /proc/{pid}/maps",
        "fds": f"ls -l /proc/{pid}/fd",
        "status": f"cat /proc/{pid}/status",
        "threads": f"cat /proc/{pid}/task/*/comm",
        "thread-status": f"cat /proc/{pid}/task/*/status",
    }
    maps_report: dict[str, int] = {}
    thread_report: dict[str, object] = {}
    for label, command in commands.items():
        result = root_shell(serial, command)
        assert_clean_proc_text(label, result.stdout)
        if label == "maps":
            maps_report = analyze_proc_maps(result.stdout)
            if require_no_anonymous_rwx and maps_report["anonymous_rwx"]:
                raise SmokeFailure(
                    f"maps contains {maps_report['anonymous_rwx']} anonymous RWX mapping(s)"
                )
        elif label == "thread-status":
            thread_report = analyze_thread_statuses(result.stdout)
    marker_arguments = " ".join(MEMORY_SCAN_MARKERS)
    result = root_shell(
        serial,
        f"{memory_scanner} {pid} {mapping_needle} {marker_arguments}",
    )
    report: dict[str, object] = {}
    report.update(_parse_memory_scan(mapping_needle, result.stdout))
    report["maps"] = maps_report
    report["threads"] = thread_report
    return report


def _run_gadget_script_acceptance(device: Any, pid: int) -> None:
    session: Any = None
    outcome: dict[str, Any] = {}
    completed = threading.Event()

    def on_message(message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "error":
            outcome["error"] = message.get("stack") or message.get("description") or message
            completed.set()
            return
        payload = message.get("payload")
        if (
            message.get("type") == "send"
            and isinstance(payload, dict)
            and payload.get("type") == "phantom-frida-gadget-result"
        ):
            outcome["passed"] = True
            completed.set()

    try:
        session = device.attach(pid)
        script = session.create_script(GADGET_PROBE_SOURCE)
        script.on("message", on_message)
        script.load()
        if "error" not in outcome and script.exports_sync.add(20, 22) != 42:
            raise SmokeFailure("Stock Frida RPC returned an unexpected Gadget result")
        if not completed.wait(SCRIPT_TIMEOUT_SECONDS):
            raise SmokeFailure(
                f"Frida Gadget script timed out after {SCRIPT_TIMEOUT_SECONDS} seconds"
            )
        if "error" in outcome:
            raise SmokeFailure(f"Gadget script error: {outcome['error']}")
        if outcome.get("passed") is not True:
            raise SmokeFailure("Frida Gadget script returned no structured result")
    except SmokeFailure:
        raise
    except Exception as error:
        raise SmokeFailure(f"Frida Gadget script acceptance failed: {error}") from error
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def _find_ndk_clang(ndk: Path) -> Path:
    candidates = sorted(
        candidate
        for prebuilt in (ndk / "toolchains" / "llvm" / "prebuilt").glob("*")
        for candidate in (prebuilt / "bin" / "clang", prebuilt / "bin" / "clang.exe")
        if candidate.is_file()
    )
    if not candidates:
        raise SmokeFailure(f"NDK clang is missing under {ndk}")
    return candidates[0]


def _android_clang_target(abi: str, api_level: int) -> str:
    target_by_abi = {
        "arm64-v8a": "aarch64-linux-android",
        "armeabi-v7a": "armv7a-linux-androideabi",
        "x86_64": "x86_64-linux-android",
        "x86": "i686-linux-android",
    }
    target = target_by_abi.get(abi)
    if target is None:
        raise SmokeFailure(f"Unsupported Android ABI: {abi}")
    return f"{target}{max(api_level, 21)}"


def _compile_gadget_loader(
    config: AndroidSmokeConfig, abi: str, api_level: int, output: Path
) -> None:
    source = REPOSITORY_ROOT / "tests" / "android" / "gadget-loader.c"
    if not source.is_file():
        raise SmokeFailure(f"Gadget loader source is missing: {source}")
    run_command(
        [
            _find_ndk_clang(config.ndk),
            f"--target={_android_clang_target(abi, api_level)}",
            "-fPIE",
            "-pie",
            source,
            "-ldl",
            "-o",
            output,
        ]
    )


def _compile_proc_memory_scanner(
    config: AndroidSmokeConfig, abi: str, api_level: int, output: Path
) -> None:
    source = REPOSITORY_ROOT / "tests" / "android" / "proc-memory-scanner.c"
    if not source.is_file():
        raise SmokeFailure(f"Process memory scanner source is missing: {source}")
    run_command(
        [
            _find_ndk_clang(config.ndk),
            f"--target={_android_clang_target(abi, api_level)}",
            "-fPIE",
            "-pie",
            source,
            "-o",
            output,
        ]
    )


def _read_android_platform(serial: str) -> tuple[str, int]:
    abi = adb(serial, "shell", "getprop", "ro.product.cpu.abi").stdout.strip()
    api_text = adb(serial, "shell", "getprop", "ro.build.version.sdk").stdout.strip()
    try:
        api_level = int(api_text)
    except ValueError as error:
        raise SmokeFailure(f"Invalid Android API level reported by device: {api_text!r}") from error
    _android_clang_target(abi, api_level)
    return abi, api_level


def _prepare_proc_memory_scanner(
    config: AndroidSmokeConfig,
    serial: str,
    abi: str,
    api_level: int,
) -> str:
    remote_scanner = f"{REMOTE_DIR}/proc-memory-scanner"
    with tempfile.TemporaryDirectory(prefix="phantom-frida-scanner-") as temporary:
        scanner = Path(temporary) / "proc-memory-scanner"
        _compile_proc_memory_scanner(config, abi, api_level, scanner)
        adb(serial, "push", scanner, remote_scanner)
    adb(serial, "shell", "chmod", "755", remote_scanner)
    return remote_scanner


def _gadget_interaction(endpoint: RemoteEndpoint) -> dict[str, str]:
    return {
        "type": "listen",
        "address": f"unix:{endpoint.socket}",
        "origin": endpoint.origin,
        "token": endpoint.token,
        "on_load": "resume",
    }


def _exercise_gadget(
    config: AndroidSmokeConfig,
    serial: str,
    manager: Any,
    remote_gadget: str,
    memory_scanner: str,
    abi: str,
    api_level: int,
    *,
    require_no_anonymous_rwx: bool = False,
) -> dict[str, object]:
    gadget_port = choose_gadget_port(config.port)
    endpoint = create_remote_endpoint(config.name, "gadget")
    _configure_forward(serial, gadget_port, endpoint.socket)
    remote_loader = f"{REMOTE_DIR}/gadget-loader"
    remote_config = f"{REMOTE_DIR}/lib{config.name}-gadget.config.so"
    remote_log = f"{REMOTE_DIR}/gadget-loader.log"
    with tempfile.TemporaryDirectory(prefix="phantom-frida-gadget-") as temporary:
        temporary_dir = Path(temporary)
        loader = temporary_dir / "gadget-loader"
        gadget_config = temporary_dir / "gadget.config.so"
        _compile_gadget_loader(config, abi, api_level, loader)
        gadget_config.write_text(
            json.dumps(
                {"interaction": _gadget_interaction(endpoint)},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        adb(serial, "push", loader, remote_loader)
        adb(serial, "push", gadget_config, remote_config)
    adb(serial, "shell", "chmod", "755", remote_loader)
    root_shell(
        serial,
        f"{remote_loader} {remote_gadget} >{remote_log} 2>&1 &",
    )

    gadget_device, processes = _wait_for_remote_device(
        manager,
        f"127.0.0.1:{gadget_port}",
        endpoint,
    )
    if not processes:
        raise SmokeFailure("Stock Frida enumerated no process through Gadget")
    gadget_pid = getattr(processes[0], "pid", None)
    if not isinstance(gadget_pid, int):
        raise SmokeFailure("Stock Frida returned a Gadget process without an integer pid")
    _run_gadget_script_acceptance(gadget_device, gadget_pid)
    assert_clean_proc_text("gadget unix", root_shell(serial, "cat /proc/net/unix").stdout)
    memory_report = _scan_process_procfs(
        serial,
        gadget_pid,
        memory_scanner,
        f"lib{config.name}-gadget.so",
        require_no_anonymous_rwx=require_no_anonymous_rwx,
    )
    return {
        "abi": abi,
        "api_level": api_level,
        "port": gadget_port,
        "process_count": len(processes),
        "script_loaded": True,
        "memory": memory_report,
    }


def _parse_remote_processes(output: str, remote_executables: Sequence[str]) -> dict[str, list[int]]:
    matches: dict[str, list[int]] = {path: [] for path in remote_executables}
    for line in output.splitlines():
        match = re.search(r"/proc/(\d+)/exe -> (.+)$", line)
        if match is None:
            continue
        target = match.group(2).removesuffix(" (deleted)")
        if target in matches:
            matches[target].append(int(match.group(1)))
    return matches


def _remote_signal_command(remote_executable: str, pid: int, signal: str) -> str:
    body = (
        f"target=$(readlink /proc/{pid}/exe 2>/dev/null) || exit 0; "
        f'case "$target" in "{remote_executable}"|"{remote_executable} (deleted)") '
        f"kill -{signal} {pid} || exit 1 ;; esac; exit 0"
    )
    return f"'{body}'"


def _cleanup(config: AndroidSmokeConfig, serial: str) -> None:
    processes = (
        (f"{config.name}-server", f"{REMOTE_DIR}/{config.name}-server"),
        ("gadget-loader", f"{REMOTE_DIR}/gadget-loader"),
    )
    failures: list[str] = []
    remote_executables = tuple(path for _label, path in processes)

    def snapshot(stage: str) -> dict[str, list[int]] | None:
        result = root_shell(
            serial,
            "'ls -l /proc/[0-9]*/exe 2>/dev/null; exit 0'",
            check=False,
        )
        if result.returncode != 0:
            failures.append(f"{stage} (exit {result.returncode})")
            return None
        return _parse_remote_processes(result.stdout, remote_executables)

    initial = snapshot("list Android smoke processes")
    if initial is not None:
        for label, remote_executable in processes:
            for pid in initial[remote_executable]:
                result = root_shell(
                    serial,
                    _remote_signal_command(remote_executable, pid, "TERM"),
                    check=False,
                )
                if result.returncode != 0:
                    failures.append(f"stop {label} (exit {result.returncode})")
        if any(initial.values()):
            time.sleep(0.5)

    remaining = snapshot("verify Android smoke processes")
    forced_labels: list[str] = []
    if remaining is not None:
        for label, remote_executable in processes:
            for pid in remaining[remote_executable]:
                if label not in forced_labels:
                    forced_labels.append(label)
                result = root_shell(
                    serial,
                    _remote_signal_command(remote_executable, pid, "KILL"),
                    check=False,
                )
                if result.returncode != 0:
                    failures.append(f"force-stop {label} (exit {result.returncode})")

    if forced_labels:
        failures.append("processes did not stop gracefully: " + ", ".join(forced_labels))
        time.sleep(0.2)
        final = snapshot("verify Android smoke processes after SIGKILL")
        if final is not None:
            for label, remote_executable in processes:
                if final[remote_executable]:
                    failures.append(f"process remains: {label}")

    remove_result = root_shell(serial, f"rm -rf -- {REMOTE_DIR}", check=False)
    if remove_result.returncode != 0:
        failures.append(f"remove remote test directory (exit {remove_result.returncode})")

    for port in (config.port, choose_gadget_port(config.port)):
        adb(serial, "forward", "--remove", f"tcp:{port}", check=False)

    directory_result = root_shell(serial, f"test ! -e {REMOTE_DIR}", check=False)
    if directory_result.returncode != 0:
        failures.append("remote test directory remains")

    socket_result = root_shell(serial, "cat /proc/net/unix", check=False)
    if socket_result.returncode != 0:
        failures.append(f"list unix sockets (exit {socket_result.returncode})")
    else:
        socket_markers = (
            f"@{config.name}-server-",
            f"@{config.name}-gadget-",
            f"@/{config.name}-zymbiote-",
        )
        for marker in socket_markers:
            if marker in socket_result.stdout:
                failures.append(f"unix socket remains: {marker}")

    forward_result = adb(serial, "forward", "--list", check=False)
    if forward_result.returncode != 0:
        failures.append(f"list adb forwards (exit {forward_result.returncode})")
    else:
        for port in (config.port, choose_gadget_port(config.port)):
            if f"tcp:{port}" in forward_result.stdout:
                failures.append(f"adb forward remains: tcp:{port}")

    if failures:
        raise SmokeFailure("Android smoke cleanup failed: " + "; ".join(failures))


def run_android_smoke(config: AndroidSmokeConfig, script_path: Path) -> dict[str, object]:
    metadata = _load_build_metadata(config)
    require_no_anonymous_rwx = _strict_wx_required(metadata)
    frida_module = _load_matching_frida(config)
    agent_source = _compile_agent(frida_module, script_path)
    serial = require_single_device(run_command(["adb", "devices", "-l"]).stdout)
    root_result = root_shell(serial, "id")
    if "uid=0" not in root_result.stdout:
        raise SmokeFailure(f"adb device does not provide root through su: {root_result.stdout}")
    assert_interactive_device(
        adb(serial, "shell", "dumpsys", "power").stdout,
        adb(serial, "shell", "dumpsys", "window", "policy").stdout,
    )
    package_result = adb(serial, "shell", "pm", "path", config.package)
    if "package:" not in package_result.stdout:
        raise SmokeFailure(f"Android package is not installed: {config.package}")

    primary_error: Exception | None = None
    try:
        remote_server, remote_gadget = _prepare_remote_files(config, serial)
        abi, api_level = _read_android_platform(serial)
        memory_scanner = _prepare_proc_memory_scanner(
            config,
            serial,
            abi,
            api_level,
        )
        server_endpoint = create_remote_endpoint(config.name, "server")
        manager = frida_module.get_device_manager()
        report: dict[str, object] = {
            "frida_version": str(frida_module.__version__),
            "package": config.package,
            "server_port": config.port,
            "strict_wx": require_no_anonymous_rwx,
        }
        _configure_forward(serial, config.port, server_endpoint.socket)
        run_command(
            server_start_command(serial, remote_server, server_endpoint),
            redact=(serial, server_endpoint.token),
        )
        server_device, processes = _wait_for_remote_device(
            manager,
            f"127.0.0.1:{config.port}",
            server_endpoint,
        )
        if not processes:
            raise SmokeFailure("Stock Frida enumerated no processes through the server")
        report["server_process_count"] = len(processes)
        report["server"] = _run_script_acceptance(
            server_device,
            serial,
            config.package,
            agent_source,
            memory_scanner,
            require_no_anonymous_rwx=require_no_anonymous_rwx,
        )
        report["gadget"] = _exercise_gadget(
            config,
            serial,
            manager,
            remote_gadget,
            memory_scanner,
            abi,
            api_level,
            require_no_anonymous_rwx=require_no_anonymous_rwx,
        )
        report["status"] = "passed"
        return report
    except Exception as error:
        primary_error = error
        raise
    finally:
        try:
            _cleanup(config, serial)
        except SmokeFailure as cleanup_error:
            if primary_error is not None:
                raise SmokeFailure(
                    f"{primary_error}; cleanup also failed: {cleanup_error}"
                ) from primary_error
            raise


def _write_report(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        **{key: value for key, value in payload.items() if key != "device_serial"},
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--gadget", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument(
        "--script",
        type=Path,
        default=REPOSITORY_ROOT / "test_comprehensive.js",
    )
    parser.add_argument("--report", type=Path, default=Path("android-smoke-report.json"))
    args = parser.parse_args(argv)

    try:
        config = validate_config(
            server=args.server,
            gadget=args.gadget,
            name=args.name,
            port=args.port,
            package=args.package,
            ndk=args.ndk,
        )
        report = run_android_smoke(config, args.script.resolve())
    except SmokeFailure as error:
        _write_report(args.report.resolve(), {"status": "failed", "error": str(error)})
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    _write_report(args.report.resolve(), report)
    print(f"[OK] Android smoke test passed; report: {args.report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
