import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from scripts import android_smoke


def clean_memory_scan_output() -> str:
    lines = ["ranges=7", "executable=3"]
    lines.extend(f"marker={marker} count=0" for marker in android_smoke.MEMORY_SCAN_MARKERS)
    return "\n".join(lines) + "\n"


def test_proc_scan_rejects_zymbiote_socket() -> None:
    with pytest.raises(android_smoke.SmokeFailure, match="frida-zymbiote"):
        android_smoke.assert_clean_proc_text("unix", "@/frida-zymbiote-deadbeef")


def test_proc_scan_accepts_custom_runtime_names() -> None:
    android_smoke.assert_clean_proc_text(
        "unix", "@/oemcodec-zymbiote-deadbeef\n/data/local/tmp/oemcodec-server"
    )


def test_proc_scan_rejects_legacy_linjector_fd() -> None:
    with pytest.raises(android_smoke.SmokeFailure, match="linjector"):
        android_smoke.assert_clean_proc_text("fds", "pipe:[linjector-123]")


def test_proc_scan_rejects_active_tracer() -> None:
    with pytest.raises(android_smoke.SmokeFailure, match="TracerPid"):
        android_smoke.assert_clean_proc_text("status", "Name:\ttarget\nTracerPid:\t123\n")


def test_proc_scan_accepts_no_tracer() -> None:
    android_smoke.assert_clean_proc_text("status", "Name:\ttarget\nTracerPid:\t0\n")


def test_proc_scan_rejects_a_tracer_on_any_thread() -> None:
    statuses = "Name:\tmain\nTracerPid:\t0\nName:\tworker\nTracerPid:\t321\n"

    with pytest.raises(android_smoke.SmokeFailure, match="TracerPid"):
        android_smoke.assert_clean_proc_text("thread-status", statuses)


def test_proc_maps_report_distinguishes_anonymous_rwx_from_art_jit() -> None:
    report = android_smoke.analyze_proc_maps(
        """1000-2000 r-xs 00000000 00:01 42 /memfd:jit-cache (deleted)
2000-3000 rwxp 00000000 00:00 0
3000-5000 r-xp 00000000 00:01 43 /memfd:jit-code-cache (deleted)
5000-6000 rw-p 00000000 00:00 0 [anon:scudo:primary]
"""
    )

    assert report == {
        "executable": 3,
        "rwx": 1,
        "anonymous_rwx": 1,
        "deleted_executable": 2,
        "memfd_executable": 2,
    }


@pytest.mark.parametrize("path", ["[anon:gum-code]", "[stack]"])
def test_proc_maps_report_treats_bracketed_rwx_as_anonymous(path: str) -> None:
    report = android_smoke.analyze_proc_maps(f"7000-8000 rwxp 00000000 00:00 0 {path}\n")

    assert report["anonymous_rwx"] == 1


def test_thread_status_report_counts_tracers_and_signal_masks() -> None:
    report = android_smoke.analyze_thread_statuses(
        """Name:\tmain
TracerPid:\t0
SigBlk:\t0000000080001204
Name:\tworker
TracerPid:\t42
SigBlk:\t0000000080005204
Name:\tworker2
TracerPid:\t0
SigBlk:\t0000000080001204
"""
    )

    assert report == {
        "threads": 3,
        "nonzero_tracer": 1,
        "sigblk": {
            "0000000080001204": 2,
            "0000000080005204": 1,
        },
    }


@pytest.mark.parametrize(
    "marker",
    [
        "frida-gadget",
        "frida-eternal-agent",
        "frida-generate-certificate",
        "frida-main-loop",
        "gum-js-loop",
        "gmain",
        "gdbus",
        "pool-frida",
        "pool-spawner",
    ],
)
def test_proc_scan_rejects_modern_runtime_thread_markers(marker: str) -> None:
    with pytest.raises(android_smoke.SmokeFailure, match=marker):
        android_smoke.assert_clean_proc_text("threads", marker)


def test_proc_scan_uses_portable_single_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[str] = []

    def fake_root_shell(_serial: str, command: str) -> SimpleNamespace:
        commands.append(command)
        if command.endswith("/maps"):
            output = "1000-2000 r-xp 00000000 00:01 42 /memfd:jit-code-cache (deleted)\n"
        elif command.endswith("task/*/status"):
            output = "Name:\tmain\nTracerPid:\t0\nSigBlk:\t0000000080001204\n"
        elif "proc-memory-scanner" in command:
            output = clean_memory_scan_output()
        else:
            output = ""
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)

    report = android_smoke._scan_process_procfs(
        "SERIAL-1",
        123,
        "/data/local/tmp/phantom-frida-test/proc-memory-scanner",
        "memfd:jit-code-cache",
    )

    assert commands[:6] == [
        "cat /proc/net/unix",
        "cat /proc/123/maps",
        "ls -l /proc/123/fd",
        "cat /proc/123/status",
        "cat /proc/123/task/*/comm",
        "cat /proc/123/task/*/status",
    ]
    assert commands[6].startswith(
        "/data/local/tmp/phantom-frida-test/proc-memory-scanner 123 memfd:jit-code-cache"
    )
    assert report == {
        "ranges": 7,
        "executable": 3,
        "maps": {
            "executable": 1,
            "rwx": 0,
            "anonymous_rwx": 0,
            "deleted_executable": 1,
            "memfd_executable": 1,
        },
        "threads": {
            "threads": 1,
            "nonzero_tracer": 0,
            "sigblk": {"0000000080001204": 1},
        },
    }


def test_proc_scan_rejects_anonymous_rwx_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_root_shell(_serial: str, command: str) -> SimpleNamespace:
        if command.endswith("/maps"):
            output = "1000-2000 rwxp 00000000 00:00 0\n"
        elif command.endswith("task/*/status"):
            output = "Name:\tmain\nTracerPid:\t0\nSigBlk:\t0000000000000000\n"
        elif "proc-memory-scanner" in command:
            output = clean_memory_scan_output()
        else:
            output = ""
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)

    with pytest.raises(android_smoke.SmokeFailure, match="anonymous RWX"):
        android_smoke._scan_process_procfs(
            "SERIAL-1",
            123,
            "/data/local/tmp/phantom-frida-test/proc-memory-scanner",
            "memfd:jit-code-cache",
            require_no_anonymous_rwx=True,
        )


def test_memory_scan_rejects_runtime_signature() -> None:
    output = clean_memory_scan_output().replace(
        "marker=frida:rpc count=0",
        "marker=frida:rpc count=2",
    )

    with pytest.raises(android_smoke.SmokeFailure, match="frida:rpc=2"):
        android_smoke._parse_memory_scan("server agent", output)


def test_memory_scan_requires_matching_memory_ranges() -> None:
    output = clean_memory_scan_output().replace("ranges=7", "ranges=0")

    with pytest.raises(android_smoke.SmokeFailure, match="no matching memory ranges"):
        android_smoke._parse_memory_scan("server agent", output)


def test_proc_memory_scanner_is_compiled_for_device_abi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clang = tmp_path / "ndk/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
    clang.parent.mkdir(parents=True)
    clang.write_bytes(b"")
    output = tmp_path / "proc-memory-scanner"
    commands: list[list[str]] = []
    monkeypatch.setattr(
        android_smoke,
        "run_command",
        lambda command, **_kwargs: commands.append([str(part) for part in command]),
    )
    config = SimpleNamespace(ndk=tmp_path / "ndk")

    android_smoke._compile_proc_memory_scanner(config, "arm64-v8a", 34, output)

    assert commands == [
        [
            str(clang),
            "--target=aarch64-linux-android34",
            "-fPIE",
            "-pie",
            str(android_smoke.REPOSITORY_ROOT / "tests/android/proc-memory-scanner.c"),
            "-o",
            str(output),
        ]
    ]


def test_gadget_port_does_not_collide_with_server() -> None:
    assert android_smoke.choose_gadget_port(27142) == 27143
    assert android_smoke.choose_gadget_port(65535) == 27043
    assert android_smoke.choose_gadget_port(27041) == 27043


def test_require_single_device_returns_only_authorized_serial() -> None:
    output = "List of devices attached\nSERIAL-1\tdevice product:test\n\n"
    assert android_smoke.require_single_device(output) == "SERIAL-1"


def test_interactive_device_preflight_accepts_unlocked_screen() -> None:
    android_smoke.assert_interactive_device(
        "mWakefulness=Awake\n",
        "mInputRestricted=false\n",
    )


@pytest.mark.parametrize(
    ("power", "policy", "reason"),
    [
        ("mWakefulness=Dozing\n", "mInputRestricted=false\n", "awake"),
        ("mWakefulness=Awake\n", "mInputRestricted=true\n", "unlocked"),
        ("mWakefulness=Awake\n", "KeyguardServiceDelegate\n", "unlocked"),
    ],
)
def test_interactive_device_preflight_rejects_blocked_spawn_state(
    power: str, policy: str, reason: str
) -> None:
    with pytest.raises(android_smoke.SmokeFailure, match=reason):
        android_smoke.assert_interactive_device(power, policy)


@pytest.mark.parametrize(
    "output,count",
    [
        ("List of devices attached\n", 0),
        ("List of devices attached\nSERIAL\tunauthorized\n", 0),
        ("List of devices attached\nONE\tdevice\nTWO\tdevice\n", 2),
    ],
)
def test_require_single_device_rejects_invalid_device_count(output: str, count: int) -> None:
    with pytest.raises(android_smoke.SmokeFailure, match=f"found {count}"):
        android_smoke.require_single_device(output)


def test_server_start_command_uses_authenticated_abstract_socket() -> None:
    endpoint = android_smoke.RemoteEndpoint(
        socket="oemcodec-server-a1b2c3",
        origin="https://a1b2c3.invalid",
        token="secret-token",
    )

    assert android_smoke.server_start_command(
        "SERIAL-1", "/data/local/tmp/phantom-frida-test/oemcodec-server", endpoint
    ) == [
        "adb",
        "-s",
        "SERIAL-1",
        "shell",
        "su",
        "-c",
        (
            "/data/local/tmp/phantom-frida-test/oemcodec-server "
            "-l unix:oemcodec-server-a1b2c3 "
            "--origin https://a1b2c3.invalid --token secret-token -D </dev/null "
            ">/data/local/tmp/phantom-frida-test/server.log 2>&1"
        ),
    ]


def test_run_command_redacts_authentication_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        android_smoke.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )

    android_smoke.run_command(
        ["client", "--options=origin,token=secret-token"],
        redact=("secret-token",),
    )

    output = capsys.readouterr().out
    assert "secret-token" not in output
    assert "<redacted>" in output


def test_adb_forward_targets_abstract_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        android_smoke,
        "adb",
        lambda *args, **kwargs: calls.append((*args, kwargs)),
    )

    android_smoke._configure_forward("SERIAL-1", 27142, "oemcodec-server-a1b2c3")

    assert calls == [
        ("SERIAL-1", "forward", "--remove", "tcp:27142", {"check": False}),
        ("SERIAL-1", "forward", "tcp:27142", "localabstract:oemcodec-server-a1b2c3", {}),
    ]


def test_gadget_config_uses_authenticated_abstract_socket() -> None:
    endpoint = android_smoke.RemoteEndpoint(
        socket="oemcodec-gadget-a1b2c3",
        origin="https://a1b2c3.invalid",
        token="secret-token",
    )

    config = android_smoke._gadget_interaction(endpoint)

    assert config == {
        "type": "listen",
        "address": "unix:oemcodec-gadget-a1b2c3",
        "origin": "https://a1b2c3.invalid",
        "token": "secret-token",
        "on_load": "resume",
    }
    assert "port" not in config


def test_validate_config_normalizes_builder_inputs(tmp_path: Path) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()

    config = android_smoke.validate_config(
        server=server,
        gadget=gadget,
        name="OemCodec",
        port=27142,
        package="com.example.app",
        ndk=ndk,
    )

    assert config.name == "oemcodec"
    assert config.port == 27142


@pytest.mark.parametrize("package", ["", "single", "com.example;id", "9com.example"])
def test_validate_config_rejects_unsafe_package(tmp_path: Path, package: str) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()

    with pytest.raises(android_smoke.SmokeFailure, match="package"):
        android_smoke.validate_config(
            server=server,
            gadget=gadget,
            name="oemcodec",
            port=27142,
            package=package,
            ndk=ndk,
        )


def test_remote_device_retry_does_not_register_duplicate_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeDevice:
        calls = 0

        def enumerate_processes(self) -> list[str]:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("not ready")
            return ["process"]

    class FakeManager:
        calls = 0
        device = FakeDevice()
        options: dict[str, str] = {}

        def add_remote_device(self, _address: str, **options: str) -> FakeDevice:
            self.calls += 1
            self.options = options
            return self.device

    manager = FakeManager()
    monkeypatch.setattr(android_smoke.time, "sleep", lambda _seconds: None)

    endpoint = android_smoke.RemoteEndpoint(
        socket="oemcodec-server-a1b2c3",
        origin="https://a1b2c3.invalid",
        token="secret-token",
    )
    device, processes = android_smoke._wait_for_remote_device(
        manager,
        "127.0.0.1:27142",
        endpoint,
        timeout=1,
    )

    assert device is manager.device
    assert processes == ["process"]
    assert manager.calls == 1
    assert manager.options == {
        "origin": "https://a1b2c3.invalid",
        "token": "secret-token",
    }


def test_gadget_acceptance_loads_script_and_detaches() -> None:
    class FakeScript:
        callback: object = None

        class Exports:
            @staticmethod
            def add(left: int, right: int) -> int:
                return left + right

        exports_sync = Exports()

        def on(self, _event: str, callback: object) -> None:
            self.callback = callback

        def load(self) -> None:
            assert callable(self.callback)
            self.callback(
                {
                    "type": "send",
                    "payload": {"type": "phantom-frida-gadget-result"},
                },
                None,
            )

    class FakeSession:
        detached = False
        source = ""

        def create_script(self, source: str) -> FakeScript:
            self.source = source
            return FakeScript()

        def detach(self) -> None:
            self.detached = True

    class FakeDevice:
        attached_pid = 0
        session = FakeSession()

        def attach(self, pid: int) -> FakeSession:
            self.attached_pid = pid
            return self.session

    device = FakeDevice()

    android_smoke._run_gadget_script_acceptance(device, 4242)

    assert device.attached_pid == 4242
    assert "phantom-frida-gadget-result" in device.session.source
    assert device.session.detached is True


def test_gadget_acceptance_propagates_script_errors() -> None:
    class ErrorScript:
        callback: object = None

        def on(self, _event: str, callback: object) -> None:
            self.callback = callback

        def load(self) -> None:
            assert callable(self.callback)
            self.callback({"type": "error", "description": "probe failed"}, None)

    class ErrorSession:
        detached = False

        def create_script(self, _source: str) -> ErrorScript:
            return ErrorScript()

        def detach(self) -> None:
            self.detached = True

    class ErrorDevice:
        session = ErrorSession()

        def attach(self, _pid: int) -> ErrorSession:
            return self.session

    device = ErrorDevice()

    with pytest.raises(android_smoke.SmokeFailure, match="Gadget script error: probe failed"):
        android_smoke._run_gadget_script_acceptance(device, 4242)

    assert device.session.detached is True


def test_host_frida_version_must_match_build_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()
    (tmp_path / "build-info.json").write_text('{"frida_version": "17.16.3"}', encoding="utf-8")
    config = android_smoke.validate_config(
        server=server,
        gadget=gadget,
        name="oemcodec",
        port=27142,
        package="com.example.app",
        ndk=ndk,
    )
    fake_frida = ModuleType("frida")
    fake_frida.__version__ = "17.7.2"
    monkeypatch.setattr(
        android_smoke.importlib,
        "import_module",
        lambda _name: fake_frida,
    )

    with pytest.raises(android_smoke.SmokeFailure, match="version mismatch"):
        android_smoke._load_matching_frida(config)


def test_build_metadata_exposes_the_strict_wx_acceptance_gate(tmp_path: Path) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()
    (tmp_path / "build-info.json").write_text(
        '{"frida_version": "17.16.4", "strict_wx": true}',
        encoding="utf-8",
    )
    config = android_smoke.validate_config(
        server=server,
        gadget=gadget,
        name="oemcodec",
        port=27142,
        package="com.example.app",
        ndk=ndk,
    )

    metadata = android_smoke._load_build_metadata(config)

    assert metadata["frida_version"] == "17.16.4"
    assert android_smoke._strict_wx_required(metadata) is True


def test_strict_wx_metadata_rejects_non_boolean_values() -> None:
    with pytest.raises(android_smoke.SmokeFailure, match="strict_wx must be boolean"):
        android_smoke._strict_wx_required({"strict_wx": "true"})


def test_agent_is_bundled_with_frida_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "agent.js"
    script.write_text("export const value = 1;", encoding="utf-8")
    bridge = tmp_path / "node_modules/frida-java-bridge"
    bridge.mkdir(parents=True)
    calls: dict[str, str] = {}

    class FakeCompiler:
        def on(self, _event: str, _callback: object) -> None:
            return None

        def build(self, entrypoint: str, *, project_root: str) -> str:
            calls["entrypoint"] = entrypoint
            calls["project_root"] = project_root
            return "bundled-agent"

    class FakeFrida:
        @staticmethod
        def Compiler() -> FakeCompiler:
            return FakeCompiler()

    monkeypatch.setattr(android_smoke, "JAVA_BRIDGE_DIR", bridge)

    assert android_smoke._compile_agent(FakeFrida(), script) == "bundled-agent"
    assert calls["entrypoint"] == str(script)
    assert calls["project_root"] == str(android_smoke.REPOSITORY_ROOT)


def test_acceptance_agent_uses_frida_17_file_and_java_wrapper_apis() -> None:
    source = (android_smoke.REPOSITORY_ROOT / "test_comprehensive.js").read_text(encoding="utf-8")

    assert ".readAllText()" not in source
    assert source.count("File.readAllText(") == 2
    assert "Java.cast(iterator.next(), Thread).getName()" in source
    assert "rpc.exports" in source
    assert "add(left, right)" in source
    assert "new NativeCallback" in source
    assert "Interceptor.attach" in source
    assert "new NativeFunction" in source
    assert "Stalker.follow" in source
    assert "Stalker.unfollow" in source
    assert "Stalker.garbageCollect" in source


def test_report_writer_omits_device_serial(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"

    android_smoke._write_report(
        report_path,
        {"status": "passed", "device_serial": "SECRET-SERIAL"},
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert "device_serial" not in report


def test_adb_redacts_serial_from_command_and_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    serial = "SECRET-SERIAL"

    def fail_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr=f"adb: device '{serial}' not found",
        )

    monkeypatch.setattr(subprocess, "run", fail_run)

    with pytest.raises(android_smoke.SmokeFailure) as failure:
        android_smoke.adb(serial, "shell", "id")

    rendered = capsys.readouterr().out + str(failure.value)
    assert serial not in rendered
    assert "<redacted>" in rendered


def test_cleanup_removes_remote_test_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    root_commands: list[str] = []
    adb_commands: list[tuple[str, ...]] = []
    snapshot_calls = 0

    def fake_root_shell(_serial: str, command: str, **_kwargs: object) -> SimpleNamespace:
        nonlocal snapshot_calls
        root_commands.append(command)
        stdout = ""
        if "/proc/[0-9]*/exe" in command:
            snapshot_calls += 1
            if snapshot_calls == 1:
                stdout = (
                    "lrwxrwxrwx root /proc/101/exe -> "
                    "/data/local/tmp/phantom-frida-test/oemcodec-server\n"
                    "lrwxrwxrwx root /proc/102/exe -> "
                    "/data/local/tmp/phantom-frida-test/gadget-loader\n"
                )
        return SimpleNamespace(
            returncode=1 if command.startswith(("pkill", "pgrep")) else 0,
            stdout=stdout,
            stderr="",
        )

    def fake_adb(_serial: str, *arguments: str, **_kwargs: object) -> SimpleNamespace:
        adb_commands.append(arguments)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)
    monkeypatch.setattr(android_smoke, "adb", fake_adb)
    monkeypatch.setattr(android_smoke.time, "sleep", lambda _seconds: None)
    config = SimpleNamespace(name="oemcodec", port=27142)

    android_smoke._cleanup(config, "SERIAL-1")

    term_commands = [command for command in root_commands if "kill -TERM" in command]
    assert len(term_commands) == 2
    assert all("readlink /proc/" in command for command in term_commands)
    assert any(
        "/data/local/tmp/phantom-frida-test/oemcodec-server" in command for command in term_commands
    )
    assert any(
        "/data/local/tmp/phantom-frida-test/gadget-loader" in command for command in term_commands
    )
    assert not any(command.startswith("pkill") for command in root_commands)
    assert "rm -rf -- /data/local/tmp/phantom-frida-test" in root_commands
    assert ("forward", "--list") in adb_commands


def test_cleanup_attempts_every_step_and_reports_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_commands: list[str] = []
    adb_commands: list[tuple[str, ...]] = []

    def fake_root_shell(_serial: str, command: str, **_kwargs: object) -> SimpleNamespace:
        root_commands.append(command)
        if command.startswith("rm -rf"):
            return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
        return SimpleNamespace(
            returncode=1 if command.startswith(("pkill", "pgrep")) else 0,
            stdout="",
            stderr="",
        )

    def fake_adb(_serial: str, *arguments: str, **_kwargs: object) -> SimpleNamespace:
        adb_commands.append(arguments)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)
    monkeypatch.setattr(android_smoke, "adb", fake_adb)
    config = SimpleNamespace(name="oemcodec", port=27142)

    with pytest.raises(android_smoke.SmokeFailure, match="remove remote test directory"):
        android_smoke._cleanup(config, "SERIAL-1")

    assert len([command for command in root_commands if "/proc/[0-9]*/exe" in command]) == 2
    assert not any(command.startswith(("pkill", "pgrep")) for command in root_commands)
    assert ("forward", "--remove", "tcp:27142") in adb_commands
    assert ("forward", "--remove", "tcp:27143") in adb_commands
    assert ("forward", "--list") in adb_commands


def test_cleanup_rejects_lingering_forward(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_root_shell(_serial: str, command: str, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=1 if command.startswith(("pkill", "pgrep")) else 0,
            stdout="",
            stderr="",
        )

    def fake_adb(_serial: str, *arguments: str, **_kwargs: object) -> SimpleNamespace:
        stdout = (
            "SERIAL-1 tcp:27142 localabstract:oemcodec-server\n"
            if arguments
            == (
                "forward",
                "--list",
            )
            else ""
        )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)
    monkeypatch.setattr(android_smoke, "adb", fake_adb)
    config = SimpleNamespace(name="oemcodec", port=27142)

    with pytest.raises(android_smoke.SmokeFailure, match="forward remains"):
        android_smoke._cleanup(config, "SERIAL-1")


def test_cleanup_rejects_lingering_runtime_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_root_shell(_serial: str, command: str, **_kwargs: object) -> SimpleNamespace:
        stdout = "@/oemcodec-zymbiote-deadbeef\n" if command == "cat /proc/net/unix" else ""
        return SimpleNamespace(
            returncode=1 if command.startswith(("pkill", "pgrep")) else 0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)
    monkeypatch.setattr(
        android_smoke,
        "adb",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    config = SimpleNamespace(name="oemcodec", port=27142)

    with pytest.raises(android_smoke.SmokeFailure, match="unix socket remains"):
        android_smoke._cleanup(config, "SERIAL-1")


def test_remote_signal_is_scoped_to_exact_long_name_executable() -> None:
    remote_executable = "/data/local/tmp/phantom-frida-test/abcdefghijklmnopqrst-server"

    command = android_smoke._remote_signal_command(remote_executable, 123, "TERM")

    assert "readlink /proc/123/exe" in command
    assert remote_executable in command
    assert "kill -TERM 123" in command
    assert "pkill" not in command


def test_parse_remote_processes_excludes_same_basename_outside_test_directory() -> None:
    remote_executable = "/data/local/tmp/phantom-frida-test/oemcodec-server"
    output = (
        f"lrwxrwxrwx root /proc/101/exe -> {remote_executable}\n"
        f"lrwxrwxrwx root /proc/102/exe -> {remote_executable} (deleted)\n"
        "lrwxrwxrwx root /proc/103/exe -> /other/path/oemcodec-server\n"
    )

    assert android_smoke._parse_remote_processes(output, (remote_executable,)) == {
        remote_executable: [101, 102]
    }
