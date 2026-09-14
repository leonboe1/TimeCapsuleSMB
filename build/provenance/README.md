# Independent router payload builds

Each lane contains a manifest, compressed build logs, the final Samba linker map,
and the applied SDK/Samba source diffs. Artifact hashes also appear in
`src/timecapsulesmb/assets/artifact-manifest.json`. The recorded source commit and
file hashes identify the build inputs; logs and final outputs have separate hashes.
Use `gzip -dc FILE.gz` to inspect the evidence.

The builder was an isolated NetBSD 10.1 aarch64 VM. `builder.json` identifies its
downloaded image, installed packages, and host tool hashes. The cross compilers and
target libraries were built from the pinned official NetBSD source trees. This
still trusts the prebuilt VM and host tools; it is not a compiler bootstrap proof.
No router was contacted or modified, and no router credentials or host directory
shares were provided to the VM.

The `netbsd7` SDK supplies the existing earmv4 ABI used by the project's NetBSD 6
payload family. The other lanes retain the NetBSD 4 little- and big-endian ABIs.
All payloads must be static ARM ELF executables. Samba retains the 10 MiB limit.

## Build commands

From the recorded fork commit, on the builder with the recorded packages:

```sh
SDK_JOBS=4 ./build/download.sh
SDK_JOBS=4 ./build/bootstrap.sh
./build/downloadsamba4x.sh
./build/mdns.sh
./build/nbns.sh
./build/service.sh
SAMBA4X_JOBS=2 SAMBA4X_GENERATE_CROSS_ANSWERS=0 ./build/samba4x.sh
```

Use the `oldle` or `oldbe` wrapper suffix for NetBSD 4. Those two SDK lanes share
one source tree, so download it once before running their separate bootstraps.
Do not reset that shared source while either build is running. Offline builds use
the checked-in cross answers. Enabling generated answers or device regression
execution requires a real test device and was not part of this rebuild.

Run `python3.12 build/record_provenance.py --help` for the capture arguments.
The source checkout must be clean. Capture each lane's stage directory, SDK,
Samba build directory and linker map, then compare the copied payloads against
the captured hashes before updating the artifact manifest.

## Reading the evidence

`repeat_build_checks` records actual byte comparisons where performed. An absent
entry means that repeat-build comparison was not performed. It does not imply
that every build input or output is reproducible across machines.

`sdk_distribution_complete` distinguishes a finished full operating-system build
from a log snapshot taken after the required SDK libraries were installed. The
application builds do not require completion of unrelated NetBSD userland tools.
The Samba and helper logs describe completed payload builds in either case.

`linked_archive_sha256` includes archives named by the linker map. A `LOAD` line
alone does not establish that an archive contributed code: inspect its extracted
members and retained sections. In particular, unused SDK libraries can occur in
the link command alongside the updated third-party dependencies.

These records cover the router executables. Python dependencies are separately
pinned in the root requirements files. A future macOS app also depends on its
selected native tool packages; app signing and package validation do not replace
an audit of those inputs or testing on Apple's modified kernel and filesystem.
