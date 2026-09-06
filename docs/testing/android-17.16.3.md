# Android acceptance: Frida 17.16.3

Tested on 2026-07-22 with CI-built Frida 17.16.3 Android arm64 artifacts.
Their exact hashes are recorded below.

## Environment

| Component | Value |
|---|---|
| Device | Samsung SM-G955F |
| Android | LineageOS 21 (Android 14, API 34) |
| ABI | `arm64-v8a` |
| Root | MagiskSU 30.7 |
| Host client | Unmodified Frida Python bindings 17.16.3 |
| Android NDK | r29 (`29.0.14206865`) |
| Test package | `com.android.calculator2` |

The device serial, unrelated package list, and other personal device data were
not retained. The generated local JSON report also omits the serial and is
excluded from Git.

## Artifacts

| File | SHA-256 |
|---|---|
| `oemcodec-server-17.16.3-android-arm64` | `68a359b84eac175e6d1e26dab425f53f859b1e54b2c8d0f1d8447c9df737f379` |
| `oemcodec-server-17.16.3-android-arm64.gz` | `b93213800986eebd96b2389725be8b961e1606750ef730626092c0fdcb7a7bc7` |
| `oemcodec-gadget-17.16.3-android-arm64.so` | `40a2a15086e8acc70901ca78a3169a29c43bd1ee7a7d6a115a3448fdcfc46a20` |
| `oemcodec-gadget-17.16.3-android-arm64.so.gz` | `988b40a88bb4afadeae6661657a92c6c8c795d8714022a38d0eac941f8088ae0` |

`SHA256SUMS` independently verified all four files before the device run. The
uncompressed server and Gadget were identified as AArch64 ELF artifacts.
`build-info.json` records builder commit
`b1a9493aa0b26eea8410474a923c56445836d638`, Frida commit
`954a1c4280fb4301f25f5b3026b407874c7fe5e4`, and frida-core commit
`5d714719bc0e7cba171c8dd400d4e0bb17db14b7`.

## Command

The acceptance harness was run from the repository root with exactly one
authorized device attached:

```powershell
.venv\Scripts\python.exe scripts\android_smoke.py `
  --server output-dl\oemcodec-server-17.16.3-android-arm64 `
  --gadget output-dl\oemcodec-gadget-17.16.3-android-arm64.so `
  --name oemcodec `
  --port 27142 `
  --package com.android.calculator2 `
  --ndk <path-to-android-ndk-r29> `
  --report android-smoke-report.json
```

The harness compiled `tests/android/gadget-loader.c` for
`aarch64-linux-android34`, generated the matching Gadget configuration, and
used port 27143 for the isolated Gadget check.

## Results

| Check | Result | Evidence |
|---|---|---|
| Root precondition | PASS | `su -c id` returned UID 0. |
| Stock client to Server | PASS | Frida 17.16.3 enumerated 153 processes in the latest run. |
| Spawn, attach, and resume | PASS | The calculator process completed the scripted lifecycle. |
| Java bridge and hook installation | PASS | `Java.available` was true and the structured agent reported no failures. |
| Authenticated transport | PASS | Server and Gadget used separate randomized abstract Unix sockets, origins, and tokens; neither exposed a device TCP listener. |
| `/proc` maps, file descriptors, status, and thread names | PASS | No forbidden runtime/thread marker or `linjector` descriptor was found, and `TracerPid` was zero. |
| External Server memory scan | PASS | A separate rooted native scanner inspected 9 readable ranges (7 executable); all 14 runtime markers had zero matches. |
| Stock client to Gadget | PASS | The separately loaded Gadget accepted Frida 17.16.3, attached to its process, loaded a probe script, received its structured result, and detached. |
| External Gadget memory scan | PASS | A separate rooted native scanner inspected 9 readable ranges (7 executable); all 14 runtime markers had zero matches. |
| Cleanup | PASS | Exact executable paths were terminated gracefully; an independent follow-up found no test process, directory, Unix socket, open file, or ADB forward. |

Redacted structured result:

```json
{
  "frida_version": "17.16.3",
  "gadget": {
    "abi": "arm64-v8a",
    "api_level": 34,
    "memory": {
      "executable": 7,
      "ranges": 9
    },
    "process_count": 1,
    "script_loaded": true
  },
  "server": {
    "java_available": true,
    "memory": {
      "executable": 7,
      "ranges": 9
    },
    "script_failures": []
  },
  "server_process_count": 153,
  "status": "passed"
}
```

## Scope boundary

This run proves the Server and Gadget paths on physical Android 14 hardware.
It also exercises the corrected JNI lookup path without reproducing the
`backend_class != null` assertion. It is not, by itself, an Android 15 device
test; Android 15 should remain a separately stated compatibility target until
it is exercised on matching hardware or an equivalent rooted test image.
