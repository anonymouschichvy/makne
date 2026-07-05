# Security Policy

## Overview

`makne` is an advanced C++17 binary-level mutation and obfuscation framework for x86/x64 PE binaries, built for **educational purposes, security research, and defensive binary analysis**. Because the tooling operates at a low level — parsing PE structures, rewriting machine code, injecting decryption stubs, and resolving imports dynamically — security issues in the engine itself can have serious consequences for users processing untrusted binaries. This policy describes how to responsibly report vulnerabilities.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest `main` branch | ✅ |
| Older tagged releases | ❌ (please upgrade) |

Only the current `main` branch receives security fixes. If you are on an older release, upgrade before reporting.

---

## Scope

The following categories of issues are **in scope** for security reports:

- **Malicious PE exploitation** — A crafted input `.exe` triggers a buffer overflow, heap corruption, integer overflow, or out-of-bounds read/write in the parser (`PolymorphicEngine`, `PEStructs`, section handling).
- **Arbitrary code execution** — A specially crafted binary causes `makne` itself to execute attacker-controlled code during parsing or transformation.
- **Path traversal / unsafe file writes** — The engine writes output to an unintended location on disk.
- **Decryptor stub injection bypass** — Logic flaws in `PayloadEncryptor` or `DecryptorGenerator` that allow the injected stub to be trivially defeated or to corrupt the host process.
- **Memory safety issues** — Use-after-free, double-free, or uninitialized memory in any transformation pass (`CodeReorderer`, `ControlFlowObfuscator`, `MetamorphicEngine`, etc.).
- **Integer overflow / underflow** — In RVA arithmetic, section offset calculations, or PE header field parsing that could corrupt output binaries or crash the engine.
- **Python binding issues** — Vulnerabilities in the `python/makne` wrapper that expose unsafe behavior to Python callers.
- **Supply chain issues** — Compromised CMake `FetchContent` dependencies (Zydis, Zycore).

The following are **out of scope**:

- Obfuscated binaries produced by `makne` being detected by AV engines (by design).
- The tool's own effectiveness at evading analysis (not a security vulnerability).
- Issues requiring physical access to the machine running `makne`.
- Theoretical weaknesses in XOR encryption quality (a known design trade-off documented in the README).

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, open a [GitHub Security Advisory](https://github.com/anonymouschichvy/makne/security/advisories/new) on this repository. This keeps the disclosure private until a fix is available.

Your report should include:

1. **Description** — A clear summary of the vulnerability and its impact.
2. **Affected component** — Which source file(s) or transformation pass are involved (e.g., `PolymorphicEngine.cpp`, `PayloadEncryptor.cpp`).
3. **Reproduction steps** — Minimal steps to reproduce, ideally including a crafted input PE or a code path description.
4. **Proof of concept** — If you have a PoC binary or script (attach as a zip), include it.
5. **Suggested fix** — Optional, but appreciated.

---

## Disclosure Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement of report | Within **72 hours** |
| Initial triage and severity assessment | Within **7 days** |
| Fix developed and reviewed | Within **30 days** (critical), **60 days** (moderate) |
| Public disclosure | After fix is released, coordinated with reporter |

If a fix requires more time than the targets above, we will communicate the delay and reason to the reporter.

---

## Severity Guidance

We use the following informal severity levels, mapped to CVSS concepts:

| Severity | Example |
|----------|---------|
| **Critical** | Arbitrary code execution via a crafted input PE |
| **High** | Heap/stack corruption reachable through normal CLI usage |
| **Medium** | Integer overflow that corrupts the output binary silently |
| **Low** | Crash (DoS) via a malformed PE that the engine fails to reject gracefully |
| **Informational** | Hardening suggestions, missing input validation for edge cases |

---

## Responsible Use Reminder

`makne` is released under the MIT License strictly for educational and defensive security research. Using this tool to obfuscate malware for unauthorized deployment violates local and international law. The maintainers assume no liability for misuse. Any reports that appear to be weaponizing the tool against third parties will not be acted upon and may be reported to relevant authorities.

---

## Credits

Reporters who responsibly disclose vulnerabilities will be credited in the relevant release notes unless they prefer to remain anonymous.
