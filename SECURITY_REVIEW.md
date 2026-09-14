# Security fork: changes and validation

This branch starts from upstream commit `f7455afc82f01b009536a73c79dc75dd95e1722c`.
It addresses the review prompted by [upstream issue 299](https://github.com/jamesyc/TimeCapsuleSMB/issues/299).
The original project is by James Chang. These changes do not establish malicious intent.

**All twelve remaining router binaries have been independently rebuilt from pinned
sources. Validation on actual Time Capsule hardware remains outstanding.**
Device identification used read-only Bonjour discovery. No router has been
authenticated to, flashed, repaired, deployed to, or configured during this work.
These changes belong to `security/harden-fork`; the fork's `main` branch tracks
upstream and does not contain this hardening.

| Review finding | Change |
| --- | --- |
| F1/F2/F9: telemetry and remotely authorized root execution | Removed router telemetry source, executables, launch/upload paths, client network telemetry, and opt-in controls. Saved opt-ins become false. |
| F3: SSH identity bypass | Require known host keys before credentials; fingerprint enrollment is explicit. Legacy insecure options cannot override verification. |
| F4/F5: unauthenticated/outdated rsync | Removed the service and all three binaries. New enable requests fail; upgrades stop and remove the old service. |
| F6: unsafe disk repair | Abort after failed unmount or an independently detected live mount. Propagate repair failures and reboot only after success. |
| F7: firmware origin/cache validation | Pin 110 Apple images by HTTPS origin, model, version, size and SHA256. Check cached and local images; reject redirects and bound downloads/decompression. |
| F8: broad SMB exposure | Default to LAN-only and reject interfaces whose LAN role cannot be identified. Preserve an existing explicit interface-policy choice. |
| F10: dependencies/provenance | Pin build source commits, archive hashes, Python dependencies/runtime and CI actions. Update crypto dependencies and build GMP/zlib independently of the legacy SDK. Replace all twelve remaining ARM executables and publish source/toolchain hashes, component inventory, linker maps and build logs. |
| F11: recoverable ACP credentials, found during patch validation | Block direct legacy ACP before opening a socket. Bootstrap and firmware recovery require an explicit one-command override on an isolated network. ACP's reversible password encoding and lack of server authentication cannot be repaired by SSH host-key verification. |
| R1: obsolete rsync requirements prevented hardened startup | Both host and boot validators check the actual four-program payload and private directory. Tests run both real validators against the deployment layout, including missing files and the supported legacy smbd location. |
| R2: uninstall removed persistent file attributes | Remove only managed programs and recovery snapshots. Keep `private/xattr.tdb`, the rest of the private directory, and other data in place. Test actual uninstall commands followed by reinstall with metadata and backup sentinels. |
| R3: interrupted updates overwrote active files without recovery | Stage all eleven files, verify SHA-256 by readback, retain previous programs, install an inert boot entry point during replacement, and install the complete boot entry point last. Restore previous programs on replacement/activation failure while leaving unsafe old boot code disabled. A RAM lock and durable transaction identity protect against concurrent or delayed clients. |
| R4: other maintenance bypassed the deployment lock | Share the device RAM lock across deployment, uninstall, activation, firmware writes, disk repair, reboot, mount requests, and disk write probes. Acquire before mutations, verify the firmware target again under the lock, preserve exclusion after uncertain disconnects, and retain reboot locks until RAM resets. Tests run real shell lock operations against temporary filesystems and hold a simulated fsck active while competing operations attempt to run. |
| R5: selected repair roots bypassed backup/metadata exclusions | Check the resolved root and protected ancestors before traversal, including explicit files and symlink targets. Backup scanning still requires the explicit flag; `.samba4` is always excluded. |
| R6: automatic repair could select a different SMB server | Require a matching configured server; an unmatched mounted share requires an explicit path even if it is the only available share. |
| R7: disabling NBNS prevented Samba from claiming TCP 445 | Stop Apple's `wcifsfs` before every Samba start/recovery independently of NBNS. Tests require successful listener cleanup before starting Samba and fail closed if cleanup fails. |
| R8: documentation promised factory restoration and recommended deleting metadata | Remove those claims and the full-folder deletion instructions. Explain retained metadata, incomplete reversal of prior settings/file changes, hardware validation limits, and the unresolved upstream settings-reset reports. |

Additional fixes keep updates/downloads on this fork, invalidate caches from other
update sources, and correct macOS resource-bundle validation. No hardened app release
has been published. An upstream app download does not contain these changes.

## Upgrade behavior

An upgrade must stop old telemetry and debug activity before continuing. Cleanup
never invokes an old downloaded executable, including its `--cleanup` option.
A live debug process or legacy debug files can require a router restart before
cleanup is allowed. This is an upgrade control, not proof that a previously
compromised router is clean.

Enroll an independently verified SSH fingerprint with `tcapsule trust-host` as
shown in the README. Unknown/changed keys stop the connection. Removing the
fingerprint checks would defeat this protection.

Direct legacy ACP remains insecure even with pinned SSH keys. Its packet header
XORs the administrator password with a public constant, allowing recovery of the
encoded password bytes. ACP also lacks authenticated server identity. The fork
blocks ACP before opening a socket unless `TCAPSULE_ALLOW_INSECURE_ACP=1` is set
for that command. This exception is for necessary setup/recovery on an isolated
network; it does not make ACP secure. See the README for the bootstrap procedure.

## Rebuild and regression evidence

The NetBSD 7, NetBSD 4 little-endian, and NetBSD 4 big-endian SDK distributions and
all three payload builds completed. The NetBSD 7 SDK retains the existing ABI used
by the NetBSD 6 payload family. All twelve ELF files are static ARM executables;
all three Samba binaries remain below the existing 10 MiB size limit.

All nine native helpers matched repeat builds byte for byte. A clean rebuild of
the NetBSD 7 Samba binary, including its third-party dependencies, also produced
identical executable bytes. No equivalent repeat-build claim is made for the
other two Samba binaries or for the host toolchain.

[Build provenance](build/provenance/README.md) includes the exact inputs, component
versions, compressed logs and linker maps. Tests compare every packaged payload
with its independently built counterpart and validate the evidence hashes.
[CI](https://github.com/leonboe1/TimeCapsuleSMB/actions/workflows/ci.yml?query=branch%3Asecurity%2Fharden-fork)
runs Python tests on Linux/macOS with Python 3.10, 3.12 and 3.14, Swift tests,
native and patched-Samba sanitizer regressions, and macOS app packaging validation.

## Validation limits

Deployment recovery tests execute the generated shell against temporary local
filesystems. They inject truncated and same-length corrupt uploads, failure after
each replacement, first-install failure, process interruption at journal phases,
activation and post-upload verification failures, concurrent clients, and a reboot
followed by a delayed old client. A reboot clears a stranded RAM lock; a malformed
journal stops recovery for inspection. These tests do not simulate HFS media
damage, real power-loss durability, or Apple's boot timing.

The maintenance lock coordinates clients running this branch, not Apple firmware,
AirPort Utility, manual commands, or older clients whose maintenance paths lacked
locking. Do not mix these clients during maintenance. Only clear a stranded RAM
lock by rebooting after confirming no remote repair or firmware write remains active.
Upstream [issue 177](https://github.com/jamesyc/TimeCapsuleSMB/issues/177) reports
installation-time settings resets. The cause remains unresolved; this fork cannot
guarantee uninterrupted Wi-Fi, routing, disk sharing, or existing backup continuity.

Local source tests and an isolated NetBSD build VM cannot establish correct
behavior on Apple's modified kernels or HFS filesystem. Before using important
backups, test installation, upgrade, uninstall, actual network listeners, denied
outbound traffic, interrupted transfers, and a full Time Machine backup **and
restore** on expendable hardware. Firmware and disk-repair paths need separate
device testing with recoverable data.

The current Samba baseline is 4.25.0rc2 because the downstream patch series relies
on its stream-parent and AFP_AfpInfo fixes. It remains a release candidate, not a
stable-release assurance claim. The legacy NetBSD ABI/libc and Apple's firmware
remain limitations even after updating linked third-party libraries.
