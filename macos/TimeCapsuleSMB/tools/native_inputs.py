"""Build the host-tool layer solely from committed, authenticated inputs.

Homebrew is a publisher here, never an executable or a source of local libraries.
Only original archives are cached; every output is reconstructed before use.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

MANIFEST = Path(__file__).with_name("native-inputs.json")
REPO = Path(__file__).resolve().parents[3]
MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
MAX_EXTRACTED_SIZE = 1024 * 1024 * 1024


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise RuntimeError("Dependency download redirected outside HTTPS")
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


def verified_download(record: dict, cache: Path) -> Path:
    expected, url = record["sha256"], record["url"]
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or not url.startswith("https://"):
        raise RuntimeError("Invalid dependency input record")
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / (expected + ".archive")
    if destination.exists():
        if destination.is_symlink() or digest(destination) != expected:
            raise RuntimeError(f"Dependency checksum mismatch: {destination}")
        return destination
    headers = {}
    if url.startswith("https://ghcr.io/v2/homebrew/core/"):
        repository = url.split("/v2/", 1)[1].split("/blobs/", 1)[0]
        query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull"})
        with urllib.request.urlopen("https://ghcr.io/token?" + query, timeout=30) as response:
            headers["Authorization"] = "Bearer " + json.load(response)["token"]
    opener = urllib.request.build_opener(HTTPSRedirect())
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
        staging = Path(output.name)
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=60) as response:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ARCHIVE_SIZE:
                        raise RuntimeError("Dependency archive exceeds size limit")
                    output.write(chunk)
            output.close()
            if digest(staging) != expected:
                raise RuntimeError(f"Dependency checksum mismatch: {record.get('name', url)}")
            staging.replace(destination)
        finally:
            staging.unlink(missing_ok=True)
    return destination


def inside(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def extract_archive(archive: Path, root: Path) -> None:
    """Do not delegate security-sensitive link handling to legacy tar filters."""
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive) as tar:
        for index, member in enumerate(tar):
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or index > 50000:
                raise RuntimeError("Unsafe dependency archive path/count")
            target = root.joinpath(*relative.parts)
            if not inside(target, root):
                raise RuntimeError("Dependency archive escapes extraction root")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.exists() or target.is_symlink():
                raise RuntimeError("Duplicate dependency archive entry")
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                referent = (target.parent if member.issym() else root).joinpath(*link.parts)
                if link.is_absolute() or not inside(referent, root):
                    raise RuntimeError("Dependency archive link escapes extraction root")
                if member.issym():
                    target.symlink_to(member.linkname)
                else:
                    if not referent.is_file():
                        raise RuntimeError("Invalid dependency archive hardlink")
                    total += referent.stat().st_size
                    if total > MAX_EXTRACTED_SIZE:
                        raise RuntimeError("Extracted dependency exceeds size limit")
                    shutil.copyfile(referent, target)
                continue
            if not member.isfile():
                raise RuntimeError("Unsupported dependency archive entry type")
            total += member.size
            if total > MAX_EXTRACTED_SIZE:
                raise RuntimeError("Extracted dependency exceeds size limit")
            with tar.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def build_sshpass(record: dict, cache: Path, root: Path, architectures: tuple[str, ...]) -> tuple[dict, dict]:
    extract_archive(verified_download(record, cache), root)
    source = root / f"sshpass-{record['version']}"
    patch = REPO / "build/host/sshpass-read-errors.patch"
    subprocess.run(["patch", "--batch", "--forward", "-p1", "-i", str(patch)], cwd=source, check=True)
    subprocess.run([sys.executable, str(REPO / "build/host/test_sshpass.py"), str(source / "main.c")], check=True)
    outputs = {}
    commands = []
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DYLD_", "LD_", "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"))}
    for arch in architectures:
        output = root / f"sshpass-{arch}"
        command = ["/usr/bin/clang", "-arch", arch, "-mmacosx-version-min=14.0", "-O2",
                   "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-DHAVE_POSIX_OPENPT=1",
                   "-DHAVE_TERMIOS_H=1", '-DPACKAGE_NAME="sshpass"',
                   '-DPACKAGE_STRING="sshpass 1.10 (TimeCapsuleSMB read-error patch)"',
                   '-DPASSWORD_PROMPT="assword:"', str(source / "main.c"), "-o", str(output)]
        subprocess.run(command, env=env, check=True)
        outputs[arch] = output
        commands.append(command)
    return outputs, {**record, "patch_sha256": digest(patch), "patched_source_sha256": digest(source / "main.c"),
                     "compiler": subprocess.check_output(["/usr/bin/clang", "--version"], text=True),
                     "commands": commands}


def rpaths(loader: Path) -> list[str]:
    output = subprocess.check_output(["otool", "-l", str(loader)], text=True)
    return re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset", output)


def resolve_library(loader: Path, dependency: str, kegs: dict[str, Path], root: Path) -> Path:
    candidates = []
    for prefix in ("@@HOMEBREW_PREFIX@@/opt/", "/opt/homebrew/opt/", "/usr/local/opt/"):
        if dependency.startswith(prefix):
            name, _, relative = dependency[len(prefix):].partition("/")
            if name in kegs:
                candidates.append(kegs[name] / relative)
    for prefix in ("@@HOMEBREW_CELLAR@@/", "/opt/homebrew/Cellar/", "/usr/local/Cellar/"):
        if dependency.startswith(prefix):
            name, _, rest = dependency[len(prefix):].partition("/")
            version, _, relative = rest.partition("/")
            if name in kegs and kegs[name].name == version:
                candidates.append(kegs[name] / relative)
    if dependency.startswith("@loader_path/"):
        candidates.append(loader.parent / dependency[len("@loader_path/"):])
    if dependency.startswith("@rpath/"):
        for path in rpaths(loader):
            if path.startswith("@rpath/"):
                continue
            try:
                candidates.append(resolve_library(loader, path.rstrip("/") + "/" + dependency[len("@rpath/"):], kegs, root))
            except RuntimeError:
                pass
    for candidate in candidates:
        if inside(candidate, root) and candidate.is_file():
            return candidate.resolve()
    raise RuntimeError(f"Unapproved or missing native dependency: {dependency} from {loader.name}")


def copy_closure(sources: dict, app: Path, kegs: dict, root: Path, api) -> list[dict]:
    tools = app / "Contents/Resources/Tools/bin"
    frameworks = app / "Contents/Frameworks"
    tools.mkdir(parents=True, exist_ok=True)
    frameworks.mkdir(parents=True, exist_ok=True)
    copied, records = {}, []
    queue = [(path.resolve(), tools / name) for name, path in sources.items()]
    while queue:
        source, output = queue.pop(0)
        if source in copied:
            continue
        copied[source] = output
        shutil.copy2(source, output)
        output.chmod(0o755)
        records.append({"input_path": str(source.relative_to(root)), "input_sha256": digest(source),
                        "output_path": str(output.relative_to(app))})
        for dependency in api.macho_dependencies(source) or ():
            if dependency.startswith(("/usr/lib/", "/System/Library/")):
                continue
            library = resolve_library(source, dependency, kegs, root)
            if library == source:  # LC_ID_DYLIB, not another dependency.
                continue
            destination = copied.get(library)
            if destination is None:
                destination = frameworks / (digest(library)[:12] + "-" + library.name)
                queue.append((library, destination))
            reference = "@loader_path/" + os.path.relpath(destination, output.parent)
            api.run_quiet(["install_name_tool", "-change", dependency, reference, str(output)])
        for path in rpaths(source):
            api.run_quiet(["install_name_tool", "-delete_rpath", path, str(output)])
        api.set_macho_id_if_supported(output)
    return records


def bundle(app: Path, architectures: tuple[str, ...], cache: Path, api) -> None:
    manifest = json.loads(MANIFEST.read_text())
    if len(architectures) != 1 or architectures[0] not in manifest["architectures"]:
        raise RuntimeError("No reviewed native dependency set for this architecture; currently only arm64 packaging is available")
    arch = architectures[0]
    for name in os.environ:
        if name.startswith(("TCAPSULE_PACKAGE_SSHPASS", "TCAPSULE_PACKAGE_SMBCLIENT")):
            raise RuntimeError("Local native-tool overrides are disabled; packaging uses the reviewed input manifest")
    with tempfile.TemporaryDirectory(prefix="timecapsulesmb-native-") as directory:
        root = Path(directory).resolve()
        kegs = {}
        records = manifest["architectures"][arch]["bottles"]
        for record in records:
            print(f"Verifying native input: {record['name']} {record['version']}", file=sys.stderr)
            extraction = root / record["name"]
            extract_archive(verified_download(record, cache), extraction)
            keg = extraction / record["name"] / record["version"]
            if not keg.is_dir():
                raise RuntimeError(f"Missing reviewed keg: {keg}")
            kegs[record["name"]] = keg
        sshpass, build = build_sshpass(manifest["sshpass"], cache, root / "sshpass", architectures)
        files = copy_closure({"smbclient": kegs["samba"] / "bin/smbclient", "sshpass": sshpass[arch]}, app, kegs, root, api)
        # Only this layer changed. Python was already finalized and signed;
        # signing its nested executables again can reinterpret them as bundles.
        api.ad_hoc_codesign_macho_roots([app / "Contents/Resources/Tools/bin", app / "Contents/Frameworks"])
        api.assert_tool_architectures(app, architectures)
        api.assert_runtime_macho_architectures(app, architectures)
        api.assert_no_external_macho_dependencies(app)
        api.assert_macho_code_signatures_valid(app)
        tools = app / "Contents/Resources/Tools/bin"
        env = api.python_subprocess_env()
        env.pop("SSHPASS", None)
        version = subprocess.check_output([str(tools / "smbclient"), "--version"], env=env, text=True, timeout=10)
        expected = next(record["version"] for record in records if record["name"] == "samba")
        if version.strip() != f"Version {expected}":
            raise RuntimeError(f"Unexpected packaged smbclient version: {version}")
        missing = subprocess.run([str(tools / "sshpass"), "-e", "/usr/bin/true"], env=env, capture_output=True, timeout=10)
        if missing.returncode != 1:
            raise RuntimeError("sshpass missing-password handling failed")
        child = "import os; f=os.open('/dev/tty',os.O_RDWR); os.write(f,b'Password:'); value=os.read(f,100); raise SystemExit(0 if value==b'build-test-only\\n' else 1)"
        subprocess.run([str(tools / "sshpass"), "-d", "0", sys.executable, "-I", "-c", child],
                       env=env, input=b"build-test-only\n", capture_output=True, timeout=10, check=True)
        provenance = {"schema_version": 1, "input_manifest_sha256": digest(MANIFEST),
                      "inputs": records, "sshpass_build": build, "files": files}
        for record in files:
            record["output_sha256_before_distribution_signing"] = digest(app / record["output_path"])
        destination = app / "Contents/Resources/native-provenance.json"
        destination.write_text(json.dumps(provenance, indent=2) + "\n")
        shutil.copy2(MANIFEST, app / "Contents/Resources/native-inputs.json")
        licenses = app / "Contents/Resources/NativeLicenses"
        licenses.mkdir()
        shutil.copy2(root / "sshpass/sshpass-1.10/COPYING", licenses / "sshpass-COPYING")
        for name, keg in kegs.items():
            for pattern in ("COPY*", "LICENSE*", "AUTHORS*", "sbom.spdx.json"):
                for path in keg.glob(pattern):
                    if path.is_file() and inside(path, root):
                        shutil.copy2(path, licenses / (name + "-" + path.name))
