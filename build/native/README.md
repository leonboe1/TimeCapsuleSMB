# Native device helpers

The source manifests (`*.sources`) are shared by the device build and host
tests. Each manifest links one static executable. Object files, headers and
libraries are never deployed. No helper uses pthreads.

| Executable | Owner |
| --- | --- |
| `mdns-advertiser` | DNS-SD records, packet responses, multicast sockets and Apple port takeover |
| `nbns-advertiser` | NetBIOS queries, node status and IPv4 response selection |
| `service` | On-demand NT hashing, live CIDRs and Samba bind selection |

`common/` contains live interface discovery and the shared LAN/WAN policy.
It has no daemon, cache or runtime state file. The advertisers independently
observe current interfaces. `service` is a command-line helper, not an IPC
server. Protocol-specific socket-family probes remain with their advertisers.

Module headers declare cross-module functions. `TC_LOCAL` keeps internal
helpers static in device builds; only host regression tests define
`TC_NATIVE_TEST` to link selected internal functions. This matters on NetBSD 4,
where the linker deliberately does not use section garbage collection because
it can discard required ELF notes. Do not include implementation `.c` files.

The device manager runs `mdns-advertiser` from Flash. NBNS, service and Samba
are copied to RAM before use. This fork does not include telemetry or remote
debug execution. Upgrade cleanup stops legacy schedulers without executing
any old helper. Active debug work or leftover fixed debug files blocks migration;
restart the device to clear RAM before retrying.

## Builds and checks

Run the artifact helper in the existing NetBSD VM as root, for example
`./build/service.sh`, `./build/serviceoldle.sh`, or
`./build/serviceoldbe.sh`. `make -C build advertisers-all` builds all three
helpers for all three lanes. It never downloads or rebuilds a toolchain.

After copying stripped outputs back, wait five seconds and refresh the artifact
manifest hashes. All 9 installed artifacts must be static ARM ELF executables
with the correct byte order and NetBSD note.

From the repository root:

```sh
./build/native/host-check.sh
.venv/bin/pytest
.venv/bin/pytest -n 4 --dist loadfile
TC_NATIVE_SANITIZERS=1 UBSAN_OPTIONS=halt_on_error=1 .venv/bin/pytest tests/native tests/test_deploy_modules.py
make coverage-native
```

The native suite includes packet, interface and artifact regression cases.
Test children have deadlines and isolated workspaces. Coverage uses LLVM tools
and retains its HTML report under the printed temporary output directory.
