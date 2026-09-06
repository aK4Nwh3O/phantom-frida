import gzip
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

import build


def make_elf64_with_alloc_and_debug_sections(alloc: bytes, debug: bytes) -> bytes:
    alloc_offset = 0x100
    debug_offset = 0x200
    section_table_offset = 0x300
    section_header_size = 64
    data = bytearray(section_table_offset + (3 * section_header_size))
    data[:16] = b"\x7fELF\x02\x01\x01" + (b"\0" * 9)
    struct.pack_into("<Q", data, 0x28, section_table_offset)
    struct.pack_into("<H", data, 0x3A, section_header_size)
    struct.pack_into("<H", data, 0x3C, 3)
    data[alloc_offset : alloc_offset + len(alloc)] = alloc
    data[debug_offset : debug_offset + len(debug)] = debug
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table_offset + section_header_size,
        0,
        1,
        2,
        0,
        alloc_offset,
        len(alloc),
        0,
        0,
        1,
        0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table_offset + (2 * section_header_size),
        0,
        1,
        0,
        0,
        debug_offset,
        len(debug),
        0,
        0,
        1,
        0,
    )
    return bytes(data)


def test_verify_binary_rejects_known_runtime_markers(tmp_path: Path) -> None:
    binary = tmp_path / "server"
    binary.write_bytes(b"prefix\x00/frida-zymbiote-123\x00re/frida/HelperBackend\x00")

    with pytest.raises(build.BuildError, match="frida-zymbiote"):
        build.verify_binary(binary)


def test_verify_binary_rejects_modern_memory_and_thread_markers(tmp_path: Path) -> None:
    binary = tmp_path / "server"
    binary.write_bytes(
        b"FridaScriptEngine\0GLib-GIO\0GDBusProxy\0GumScript\0frida:rpc\0"
        b"frida-gadget\0frida-eternal-agent\0frida-main-loop\0Frida/17.16.3\0"
    )

    with pytest.raises(build.BuildError, match="FridaScriptEngine"):
        build.verify_binary(binary)


def test_verify_binary_allows_required_stock_protocol_identifiers(tmp_path: Path) -> None:
    binary = tmp_path / "server"
    binary.write_bytes(b"Frida\0re.frida.HostSession\0re.frida.GadgetSession\0")

    build.verify_binary(binary)


def test_binary_memory_patches_only_touch_runtime_alloc_sections(tmp_path: Path) -> None:
    markers = b"FridaScriptEngine\0GLib-GIO\0GDBusProxy\0GumScript\0"
    binary = tmp_path / "agent.so"
    binary.write_bytes(make_elf64_with_alloc_and_debug_sections(markers, markers))

    build.apply_binary_patches(binary, "oemcodec", extended=True)

    patched = binary.read_bytes()
    assert markers not in patched[0x100 : 0x100 + len(markers)]
    assert patched[0x200 : 0x200 + len(markers)] == markers
    assert len(patched) == len(make_elf64_with_alloc_and_debug_sections(markers, markers))


def test_binary_replacement_does_not_cross_protected_region_boundary() -> None:
    data = b"prefix-frida-suffix"
    marker_start = data.index(b"frida")

    patched, count = build.replace_bytes_in_regions(
        data,
        b"frida",
        b"libgc",
        [(0, len(data))],
        [(marker_start + 2, marker_start + 4)],
    )

    assert patched == data
    assert count == 0


def test_collect_artifacts_requires_server_and_gadget(tmp_path: Path) -> None:
    with pytest.raises(build.BuildError, match="Server artifact"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            tmp_path / "stage",
            True,
        )


def test_collect_artifacts_rejects_missing_gadget(tmp_path: Path) -> None:
    server_dir = tmp_path / "build/subprojects/frida-core/server"
    server_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"clean-server")

    with pytest.raises(build.BuildError, match="Gadget artifact"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            tmp_path / "stage",
            True,
        )


def test_collect_artifacts_returns_only_verified_staged_outputs(tmp_path: Path) -> None:
    core_build = tmp_path / "build/subprojects/frida-core"
    server_dir = core_build / "server"
    gadget_dir = core_build / "lib/gadget"
    server_dir.mkdir(parents=True)
    gadget_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"clean-server")
    (gadget_dir / "liboemcodec-gadget.so").write_bytes(b"clean-gadget")
    output_dir = tmp_path / "stage"

    outputs = build.collect_artifacts(
        tmp_path,
        "android-arm64",
        "oemcodec",
        "17.16.3",
        output_dir,
        True,
    )

    assert {path.parent for path in outputs} == {output_dir}
    assert {path.name for path in outputs} == {
        "oemcodec-server-17.16.3-android-arm64",
        "oemcodec-server-17.16.3-android-arm64.gz",
        "oemcodec-gadget-17.16.3-android-arm64.so",
        "oemcodec-gadget-17.16.3-android-arm64.so.gz",
    }
    assert not list(output_dir.glob(".staging-*"))


def test_strip_binary_uses_llvm_strip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "gadget.so"
    binary.write_bytes(b"gadget")
    strip_tool = tmp_path / "llvm-strip"
    commands: list[list[object]] = []
    monkeypatch.setattr(
        build,
        "run",
        lambda command, **_kwargs: commands.append(list(command)),
    )

    build.strip_binary(binary, strip_tool)

    assert commands == [[strip_tool, "--strip-unneeded", binary]]


def test_find_llvm_strip_accepts_linux_ndk_tool(tmp_path: Path) -> None:
    strip_tool = tmp_path / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
    strip_tool.parent.mkdir(parents=True)
    strip_tool.write_bytes(b"")

    assert build.find_llvm_strip(tmp_path) == strip_tool


def test_collect_artifacts_strips_only_staged_gadget_before_compression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core_build = tmp_path / "build/subprojects/frida-core"
    server_dir = core_build / "server"
    gadget_dir = core_build / "lib/gadget"
    server_dir.mkdir(parents=True)
    gadget_dir.mkdir(parents=True)
    server_source = server_dir / "oemcodec-server"
    gadget_source = gadget_dir / "liboemcodec-gadget.so"
    server_source.write_bytes(b"clean-server")
    gadget_source.write_bytes(b"unstripped-gadget")
    stripped: list[Path] = []

    def fake_strip(binary: Path, _tool: Path) -> None:
        stripped.append(binary)
        binary.write_bytes(b"stripped-gadget")

    monkeypatch.setattr(build, "strip_binary", fake_strip)
    output_dir = tmp_path / "stage"

    build.collect_artifacts(
        tmp_path,
        "android-arm64",
        "oemcodec",
        "17.16.3",
        output_dir,
        True,
        strip_tool=tmp_path / "llvm-strip",
    )

    gadget_output = output_dir / "oemcodec-gadget-17.16.3-android-arm64.so"
    assert [path.name for path in stripped] == [gadget_output.name]
    assert gadget_output.read_bytes() == b"stripped-gadget"
    assert gzip.decompress(gadget_output.with_suffix(".so.gz").read_bytes()) == b"stripped-gadget"
    assert gadget_source.read_bytes() == b"unstripped-gadget"


def test_collect_artifacts_does_not_promote_failed_stage(tmp_path: Path) -> None:
    core_build = tmp_path / "build/subprojects/frida-core"
    server_dir = core_build / "server"
    gadget_dir = core_build / "lib/gadget"
    server_dir.mkdir(parents=True)
    gadget_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"/frida-zymbiote-invalid")
    (gadget_dir / "liboemcodec-gadget.so").write_bytes(b"clean-gadget")
    output_dir = tmp_path / "stage"

    with pytest.raises(build.BuildError, match="frida-zymbiote"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            output_dir,
            True,
        )

    assert output_dir.is_dir()
    assert not list(output_dir.iterdir())


def test_output_transaction_replaces_stale_files_only_after_success(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "stale-server").write_bytes(b"stale")

    with build.output_transaction(output_dir) as staged_output:
        assert (output_dir / "stale-server").is_file()
        (staged_output / "current-server").write_bytes(b"current")

    assert {path.name for path in output_dir.iterdir()} == {"current-server"}
    assert not list(tmp_path.glob(".output-transaction-*"))


def test_output_transaction_preserves_previous_set_on_late_failure(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "previous-server").write_bytes(b"previous")

    with pytest.raises(build.BuildError, match="second architecture failed"):
        with build.output_transaction(output_dir) as staged_output:
            (staged_output / "first-architecture-server").write_bytes(b"partial")
            raise build.BuildError("second architecture failed")

    assert {path.name for path in output_dir.iterdir()} == {"previous-server"}
    assert not list(tmp_path.glob(".output-transaction-*"))


def test_output_transaction_restores_previous_set_when_promotion_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "previous-server").write_bytes(b"previous")
    original_replace = build.os.replace

    def fail_new_output(source: str | Path, destination: str | Path) -> None:
        if Path(source).name == "next" and Path(destination) == output_dir:
            raise OSError("simulated promotion failure")
        original_replace(source, destination)

    monkeypatch.setattr(build.os, "replace", fail_new_output)

    with pytest.raises(build.BuildError, match="Could not promote verified output directory"):
        with build.output_transaction(output_dir) as staged_output:
            (staged_output / "current-server").write_bytes(b"current")

    assert {path.name for path in output_dir.iterdir()} == {"previous-server"}
    assert not list(tmp_path.glob(".output-transaction-*"))


@pytest.mark.parametrize(
    ("work_relative", "output_relative"),
    [
        ("workspace", "workspace"),
        ("workspace", "workspace/output"),
        ("workspace/build", "workspace"),
    ],
)
def test_directory_layout_rejects_overlapping_work_and_output(
    tmp_path: Path, work_relative: str, output_relative: str
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    work_dir = tmp_path / work_relative
    output_dir = tmp_path / output_relative

    with pytest.raises(build.BuildError, match="Work and output directories must not overlap"):
        build.validate_directory_layout(repository, work_dir, output_dir)


def test_directory_layout_rejects_output_containing_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(build.BuildError, match="Output directory must not contain the repository"):
        build.validate_directory_layout(repository, tmp_path / "work", tmp_path)


def test_directory_layout_allows_default_repository_children(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    work_dir, output_dir = build.validate_directory_layout(
        repository, repository / "build", repository / "output"
    )

    assert work_dir == (repository / "build").resolve()
    assert output_dir == (repository / "output").resolve()


def test_rename_does_not_descend_into_build_directory(tmp_path: Path) -> None:
    source = tmp_path / "src"
    generated = tmp_path / "build"
    source.mkdir()
    generated.mkdir()
    (source / "frida-agent.txt").write_text("source", encoding="utf-8")
    (generated / "frida-agent.txt").write_text("generated", encoding="utf-8")

    build.rename_frida_files(tmp_path, "oemcodec")

    assert (source / "oemcodec-agent.txt").exists()
    assert (generated / "frida-agent.txt").exists()


def test_rebuild_helper_dex_fails_without_javac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "subprojects/frida-core/src/android-helper/re/frida"
    helper.mkdir(parents=True)
    (helper / "Helper.java").write_text(
        "package re.frida; public class Helper {}", encoding="utf-8"
    )
    (helper.parent.parent / "helper.dex").write_bytes(b"old-dex")
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="missing"),
    )

    with pytest.raises(build.BuildError, match="javac"):
        build.rebuild_helper_dex(tmp_path, "oemcodec")


@pytest.mark.parametrize("tool", ["javac", "jar", "java"])
def test_require_executable_names_missing_tool(tool: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)

    with pytest.raises(build.BuildError, match=tool):
        build.require_executable(tool)


def test_find_android_jar_fails_when_sdk_has_no_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", (tmp_path,))

    with pytest.raises(build.BuildError, match="android.jar"):
        build.find_android_jar()


def test_find_android_jar_uses_sdk_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    android_jar = tmp_path / "platforms/android-36/android.jar"
    android_jar.parent.mkdir(parents=True)
    android_jar.write_bytes(b"jar")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())

    assert build.find_android_jar() == android_jar


def test_find_android_jar_ignores_unrelated_recursive_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    android_jar = tmp_path / "platforms/android-36/android.jar"
    android_jar.parent.mkdir(parents=True)
    android_jar.write_bytes(b"platform")
    unrelated = tmp_path / "zzz/vendor/android.jar"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_bytes(b"unrelated")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())

    assert build.find_android_jar() == android_jar


def test_find_d8_fails_when_sdk_has_no_build_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", (tmp_path,))
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)

    with pytest.raises(build.BuildError, match="d8"):
        build.find_d8_command()


def test_find_d8_uses_sdk_jar_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d8_jar = tmp_path / "build-tools/36.0.0/lib/d8.jar"
    d8_jar.parent.mkdir(parents=True)
    d8_jar.write_bytes(b"jar")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())
    monkeypatch.setattr(
        build.shutil,
        "which",
        lambda name: "/usr/bin/java" if name == "java" else None,
    )

    assert build.find_d8_command() == [
        "/usr/bin/java",
        "-cp",
        str(d8_jar),
        "com.android.tools.r8.D8",
    ]


def test_find_d8_ignores_unrelated_recursive_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d8_jar = tmp_path / "build-tools/36.0.0/lib/d8.jar"
    d8_jar.parent.mkdir(parents=True)
    d8_jar.write_bytes(b"jar")
    unrelated = tmp_path / "zzz/vendor/d8"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_bytes(b"unrelated")
    unrelated.chmod(0o755)
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())
    monkeypatch.setattr(
        build.shutil,
        "which",
        lambda name: "/usr/bin/java" if name == "java" else None,
    )

    assert build.find_d8_command() == [
        "/usr/bin/java",
        "-cp",
        str(d8_jar),
        "com.android.tools.r8.D8",
    ]


def test_port_only_patch_preserves_extended_identifiers(tmp_path: Path) -> None:
    marker = tmp_path / "subprojects/frida-core/marker.vala"
    marker.parent.mkdir(parents=True)
    marker.write_text('27042 "FridaServer" ".frida"', encoding="utf-8")

    build.apply_port_patches(tmp_path, 27142)

    patched = marker.read_text(encoding="utf-8")
    assert patched == '27142 "FridaServer" ".frida"'


def test_validate_ndk_requires_exact_revision(tmp_path: Path) -> None:
    ndk = tmp_path / "android-ndk-r29"
    ndk.mkdir()
    (ndk / "source.properties").write_text(
        "Pkg.Desc = Android NDK\nPkg.Revision = 28.2.13676358\n",
        encoding="utf-8",
    )

    with pytest.raises(build.BuildError, match="revision"):
        build.validate_ndk(ndk)


def test_validate_ndk_accepts_documented_revision(tmp_path: Path) -> None:
    ndk = tmp_path / "android-ndk-r29"
    ndk.mkdir()
    (ndk / "source.properties").write_text(
        "Pkg.Desc = Android NDK\nPkg.Revision = 29.0.14206865\n",
        encoding="utf-8",
    )

    assert build.validate_ndk(ndk) == ndk


def test_ensure_ndk_rejects_cached_archive_with_wrong_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "android-ndk-r29-linux.zip"
    archive.write_bytes(b"not the Google NDK archive")
    commands: list[list[str]] = []
    monkeypatch.setattr(build, "run", lambda command, **_kwargs: commands.append(command))

    with pytest.raises(build.BuildError, match="checksum"):
        build.ensure_ndk(tmp_path)

    assert commands == []


def test_build_prerequisites_require_node_before_a_full_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checked: list[str] = []

    def require(name: str) -> str:
        checked.append(name)
        if name == "node":
            raise build.BuildError("Required executable is missing: node")
        return f"/usr/bin/{name}"

    monkeypatch.setattr(build, "require_executable", require)
    monkeypatch.setattr(build, "find_android_jar", lambda: tmp_path / "android.jar")
    monkeypatch.setattr(build, "find_d8_command", lambda: ["d8"])

    with pytest.raises(build.BuildError, match="node"):
        build.validate_build_prerequisites(skip_build=False)

    assert checked == ["git", "java", "javac", "jar", "make", "node"]
