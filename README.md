# 💎🦊 DiamondFox

**DiamondFox** is a portable command-line utility for temporary root access on explicitly supported Samsung Galaxy firmware builds.

The project is designed around **exact target matching, strict preflight checks, fail-closed execution, and reproducible root profiles**. DiamondFox does not treat a similar firmware version as "close enough": if the device does not match a supported profile, it stops.

> [!WARNING]
> DiamondFox is build-specific software that interacts with the Android kernel.
> An unsupported build is **unsupported**, even when the device model is otherwise identical.

---

## What DiamondFox does

DiamondFox automates the host-side work required for the supported temporary-root paths:

- detects the connected Android device through ADB
- verifies the exact device and firmware profile
- validates the required bundled artifacts before use
- applies build-specific runtime gates
- tracks the current boot where required
- runs the selected temporary-root profile
- verifies whether root was actually obtained
- shows execution progress and actionable failure information

The goal is to turn the original collection of build-specific research scripts and payloads into one predictable CLI.

---

## Supported targets

### Samsung Galaxy S23 Ultra

| Model | Codename | Firmware | Root path | Status |
|---|---|---|---|---|
| `SM-S918B` | `dm3q` | `S918BXXSAFZG1` | GhostLock-derived | ✅ Supported |
| `SM-S918B` | `dm3q` | `S918BXXSAFZH3` | GhostLock-derived | ✅ Supported |
| `SM-S918B` | `dm3q` | `S918BXXUAZZHL` | GhostLock-derived ZZHL port | ✅ Supported |

Support is tied to the **exact firmware profile**.

DiamondFox will not intentionally fall back to a "similar" build when an exact match is unavailable.

---

## ZZHL / One UI 9

`S918BXXUAZZHL` required substantially more than a simple address retarget of the earlier S23 Ultra profiles.

The successful ZZHL path includes a reworked post-UAF chain with additional runtime validation around heap reclaim, fake file-operations placement, address handling, ConfigFS-based kernel access, pipe ownership, and the final temporary-root path.

The first confirmed successful run reached:

```text
uid=0(root)
context=u:r:kernel:s0
```

on the same verified and locked ZZHL boot used for the exploit attempt.

The internal development identifier of that first successful candidate was **F156**. That identifier is research history, not the public exploit name used by DiamondFox.

---

## Temporary root

DiamondFox currently provides **temporary root**, not a persistent system modification.

A successful supported run gives temporary privileged access for the current boot. After rebooting the phone, that temporary root state is gone.

DiamondFox does **not** present this as:

- a bootloader unlock
- a Magisk installation
- a permanently patched boot image
- universal root for every S23 Ultra firmware

The exact behavior exposed to Android applications depends on the root helper used by the selected profile. A successful kernel/root verification does not automatically mean Magisk or every third-party root checker will report an installed root framework.

---

## One attempt per boot

DiamondFox writes a persistent guard immediately before the exploit workflow starts. A second attempt on the same Android boot is blocked even after DiamondFox is closed or USB is disconnected. Reboot Android before trying again. Failures that occur during asset staging, before the exploit starts, do not consume the attempt.

Application state is stored under the current user's local application-data directory unless `DIAMONDFOX_HOME` or `--data-dir` is set.

---

## Usage

Download `DiamondFox.exe` from the **GitHub Releases** page.

### Windows

Run from PowerShell, CMD, or Windows Terminal:

```powershell
.\DiamondFox.exe
```

DiamondFox will inspect the connected device before offering or starting a supported root path. A root workflow can take several minutes; keep the phone connected and wait for DiamondFox to report a final result.

Example:

```text
DiamondFox Root
===============
Device       SM-S918B / dm3q
Firmware     CP2A.260605.016.S918BXXUAZZHL
Kernel       5.15.197-android13-8-34343818-abS918BXXUAZZHL
Root method  SM-S918B ZZHL / F156
Boot guard   Ready

  1  Start temporary root
  2  Device information
  3  Install support package
  4  Installed packages
  5  Refresh
  0  Exit
```

---

## Release builds vs. source code

**The official release packages are the supported root-capable distribution of DiamondFox.**

The repository source code is provided for transparency, review, development, and contribution, but the root artifacts used by the supported profiles are distributed **only with the official DiamondFox releases**.

In other words:

> Cloning the repository is not equivalent to downloading an official root-capable DiamondFox release.

This separation is intentional. It keeps the application source reviewable without pretending that a locally compiled binary is automatically equivalent to the tested release artifact set.

For the same reason, this README does not provide "build it yourself and get the exact release" instructions.

---

## Integrity and target verification

DiamondFox treats validation as part of the root process rather than an optional warning.

Depending on the target profile, checks can include:

- device model
- device codename
- exact firmware build
- Android and kernel version
- build fingerprint
- required artifact hashes
- current boot identity
- runtime address information
- exploit-attempt state
- profile-specific intermediate gates

A failed required check stops the operation.

Example:

```text
Target mismatch

Expected: S918BXXUAZZHL
Detected: S918BXXXXXXXXX

ABORTED — unsupported firmware
```

This behavior is intentional.

---

## Root profiles and future updates

DiamondFox is intended to support additional exact firmware profiles without turning the CLI into a pile of one-off scripts.

The long-term package model is based around **`.dfx` support packages**. A DFX package can provide the metadata and artifacts required for a new supported profile while the DiamondFox CLI remains the stable host application.

The DFX format is still under development and should be considered unstable until a versioned public specification is published.

Schema 1 packages are integrity-checked but do not provide publisher authentication. DiamondFox identifies them as unsigned and requires explicit confirmation before installation.

Current built-in release profiles include:

```text
SM-S918B
├── FZG1
├── FZH3
└── ZZHL
```

---

## Safety model

Kernel exploitation is sensitive to small firmware and runtime differences.

DiamondFox therefore prefers to stop rather than guess.

The supported profiles may use measures such as:

- exact target gating
- boot-aware attempt guards
- verified runtime resolution
- integrity checks
- intermediate state validation
- fail-closed aborts
- explicit root verification

A crash, timeout, or partial milestone is **not** reported as a successful root.

Success means the selected profile reached and independently verified the expected privileged state.

---

## ADB

DiamondFox communicates with the target through Android Debug Bridge.

Before starting:

1. enable **USB debugging**
2. connect the supported device
3. authorize the computer on the device
4. avoid connecting multiple physical Android targets during a root attempt

Official Windows releases bundle the ADB components required by DiamondFox.

---

## Windows publisher warning

The current Windows release is not Authenticode-signed, so Windows may display an unknown-publisher or SmartScreen warning. Verify `DiamondFox.exe` against the `SHA256SUMS.txt` file attached to the same GitHub release before running it.

---

## Diagnostics

DiamondFox prints progress and failures to the terminal. Root profiles may also create working logs inside their package directory under `/data/local/tmp/diamondfox/` on the connected device. The current CLI does not automatically export a persistent host log.

Diagnostic output can include:

- device and firmware identifiers
- kernel version
- selected profile
- preflight results
- boot identifiers
- runtime resolver results
- execution milestones
- root verification
- failure classification

Review diagnostic output before posting it publicly.

---

## Open source and official releases

The DiamondFox application source can be reviewed and contributed to publicly.

Official root support, however, refers specifically to the **tested release packages** published by this project. A fork, locally modified executable, third-party package, or altered artifact set should not be assumed to have the same safety properties or support status.

When reporting an issue, always include the exact DiamondFox release version and firmware build.

---

## Credits and licensing

The DiamondFox host application is licensed under the MIT License. The bundled root support payloads are separately licensed derivatives of the [Root-My-Galaxy F731U project](https://github.com/youyoudezhuzhu/rmg-f731u) and the SM-S918B adaptation built from that baseline; those payloads are covered by the Apache License 2.0 rather than the host application's MIT License.

Official Windows releases also contain Android Platform Tools components. Their license and third-party notices are bundled with the executable and extracted alongside the ADB runtime.

---

## Responsible use

DiamondFox is intended for legitimate device research, development, and experimentation on hardware you own or are explicitly authorized to test.

Kernel-level research can crash the operating system and may result in data loss. Keep important data backed up before experimenting.

Do not use DiamondFox on devices you do not own or do not have permission to research.

---

## Reporting issues

For a useful bug report, include:

- DiamondFox release version
- device model
- exact firmware build
- Android version
- kernel version
- the relevant DiamondFox terminal output

Do not assume that parameters from one firmware build are transferable to another.

---

## Project status

DiamondFox is under active development.

The currently confirmed S23 Ultra support covers:

```text
S918BXXSAFZG1  ✅
S918BXXSAFZH3  ✅
S918BXXUAZZHL  ✅
```

Additional devices and firmware builds should be considered unsupported until explicitly listed.

---

<p align="center">
  <b>DiamondFox</b><br>
  Temporary root. Exact targets. No guessing.
</p>
