# Security fork: changes and validation

This branch starts from upstream commit `f7455afc82f01b009536a73c79dc75dd95e1722c`.
It addresses the review prompted by [upstream issue 299](https://github.com/jamesyc/TimeCapsuleSMB/issues/299).
The original project is by James Chang. These changes do not establish malicious intent.

**Build validation is in progress. The checked-in router binaries have not yet been
replaced by the independent rebuild. Do not deploy this intermediate snapshot.**
No router has been contacted, flashed, repaired, or configured during this work.

| Review finding | Change |
| --- | --- |
| F1/F2/F9: telemetry and remotely authorized root execution | Removed router telemetry source, executables, launch/upload paths, client network telemetry, and opt-in controls. Saved opt-ins become false. |
| F3: SSH identity bypass | Require known host keys before credentials; fingerprint enrollment is explicit. Legacy insecure options cannot override verification. |
| F4/F5: unauthenticated/outdated rsync | Removed the service and all three binaries. New enable requests fail; upgrades stop and remove the old service. |
| F6: unsafe disk repair | Abort after failed unmount or an independently detected live mount. Propagate repair failures and reboot only after success. |
| F7: firmware origin/cache validation | Pin 110 Apple images by HTTPS origin, model, version, size and SHA256. Check cached and local images; reject redirects and bound downloads/decompression. |
| F8: broad SMB exposure | Default to LAN-only and reject interfaces whose LAN role cannot be identified. Preserve an existing explicit interface-policy choice. |
| F10: dependencies/provenance | Pin build source commits, archive hashes, Python dependencies/runtime and CI actions. Update crypto dependencies and build GMP/zlib independently of the legacy SDK. Independent ARM rebuilds are in progress. |

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

## Validation limits

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
