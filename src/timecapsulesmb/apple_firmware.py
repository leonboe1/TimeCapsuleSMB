from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import os
import json
from importlib import resources
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener

from timecapsulesmb.core.paths import default_user_data_dir, safe_path_part
from timecapsulesmb.flash import FlashAnalysisError, sha256_hex


APPLE_FIRMWARE_CATALOG_URL = "https://apsu.apple.com/version.xml"
MAX_FIRMWARE_BYTES = 32 * 1024 * 1024
FIRMWARE_KEY_ISSUE_URL = "https://github.com/jamesyc/TimeCapsuleSMB/issues"
UNSUPPORTED_FIRMWARE_KEY_MESSAGE = (
    "We do not have firmware encryption keys for this AirPort firmware product yet. "
    f"Please file an issue at {FIRMWARE_KEY_ISSUE_URL} so the key can be added."
)


@dataclass(frozen=True)
class FirmwareTemplateCandidate:
    data: bytes
    source: str
    path: Path | None
    product_id: str | None
    version: str | None
    expected_size: int | None = None
    from_cache: bool = False


def default_firmware_template_cache_root() -> Path:
    return default_user_data_dir() / "firmware-templates"


def normalize_syap(value: str | int | None) -> str:
    if value is None:
        raise FlashAnalysisError("cannot select firmware template because syAP is missing")
    text = str(value).strip()
    if not text:
        raise FlashAnalysisError("cannot select firmware template because syAP is empty")
    try:
        return str(int(text, 0))
    except ValueError as exc:
        raise FlashAnalysisError(f"cannot select firmware template because syAP is invalid: {text!r}") from exc


def trusted_apple_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.scheme not in {"http", "https"} or parsed.hostname != "apsu.apple.com"
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise FlashAnalysisError("firmware URL must use the approved Apple origin")
    return parsed._replace(scheme="https").geturl()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FlashAnalysisError("firmware download redirects are not permitted")


def download_url(url: str, *, timeout: int = 60) -> bytes:
    url = trusted_apple_url(url)
    with build_opener(_NoRedirect).open(url, timeout=timeout) as response:
        data = response.read(MAX_FIRMWARE_BYTES + 1)
    if len(data) > MAX_FIRMWARE_BYTES:
        raise FlashAnalysisError("firmware download exceeds the size limit")
    return data


def pinned_firmware_entries() -> list[dict[str, object]]:
    raw = resources.files("timecapsulesmb.assets").joinpath("apple-firmware-manifest.json").read_text()
    return json.loads(raw)["firmwareUpdates"]


def _approved_entry(product_id: str, version: str, url: str) -> dict[str, object]:
    url = trusted_apple_url(url)
    for entry in pinned_firmware_entries():
        if entry["productID"] == product_id and entry["version"] == version and entry["location"] == url:
            return entry
    raise FlashAnalysisError("firmware is not in the reviewed Apple firmware manifest")


def _verify_template(data: bytes, entry: dict[str, object]) -> None:
    if len(data) != entry["sizeInBytes"] or sha256_hex(data) != entry["sha256"]:
        raise FlashAnalysisError("Apple firmware template checksum mismatch")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp:
            temp_path = Path(temp.name)
            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def load_apple_firmware_catalog(*, cache_dir: Path) -> list[dict[str, object]]:
    # Cached or newly downloaded catalogs cannot add trusted firmware hashes.
    # Updating this manifest is an explicit reviewed maintenance operation.
    return pinned_firmware_entries()


def firmware_template_cache_path(*, cache_dir: Path, product_id: str, version: str, url: str) -> Path:
    suffix = sha256_hex(url.encode("utf-8"))[:12]
    parsed_name = Path(urlparse(url).path).name or "firmware.basebinary"
    if not parsed_name.endswith(".basebinary"):
        parsed_name = f"{parsed_name}.basebinary"
    filename = f"{safe_path_part(version)}-{suffix}-{safe_path_part(parsed_name)}"
    return cache_dir / safe_path_part(product_id) / filename


def read_cached_or_download_template(entry: dict[str, object], *, cache_dir: Path) -> FirmwareTemplateCandidate:
    product_id = str(entry.get("productID") or "")
    version = str(entry.get("version") or "")
    url = str(entry.get("location") or "")
    if not product_id or not version or not url:
        raise FlashAnalysisError("Apple firmware catalog entry is missing productID, version, or location")
    entry = _approved_entry(product_id, version, url)
    url = str(entry["location"])
    expected_size = int(entry["sizeInBytes"])
    path = firmware_template_cache_path(cache_dir=cache_dir, product_id=product_id, version=version, url=url)
    if path.exists():
        with path.open("rb") as cached:
            data = cached.read(MAX_FIRMWARE_BYTES + 1)
        if len(data) == expected_size and sha256_hex(data) == entry["sha256"]:
            return FirmwareTemplateCandidate(
                data=data,
                source=url,
                path=path,
                product_id=product_id,
                version=version,
                expected_size=expected_size,
                from_cache=True,
            )

    return download_firmware_template_to_cache(
        url=url,
        path=path,
        product_id=product_id,
        version=version,
        expected_size=expected_size,
    )


def download_firmware_template_to_cache(
    *,
    url: str,
    path: Path,
    product_id: str,
    version: str,
    expected_size: int | None,
) -> FirmwareTemplateCandidate:
    entry = _approved_entry(product_id, version, url)
    url = str(entry["location"])
    expected_size = int(entry["sizeInBytes"])
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = download_url(url, timeout=120)
    except Exception as exc:
        raise FlashAnalysisError(f"failed to download Apple firmware template {url}: {exc}") from exc
    if expected_size is not None and len(data) != expected_size:
        raise FlashAnalysisError(
            f"downloaded Apple firmware template size mismatch for {url}: "
            f"got {len(data)}, expected {expected_size}"
        )
    _verify_template(data, entry)
    try:
        _atomic_write_bytes(path, data)
    except OSError as exc:
        raise FlashAnalysisError(f"failed to write Apple firmware template cache {path}: {exc}") from exc
    return FirmwareTemplateCandidate(
        data=data,
        source=url,
        path=path,
        product_id=product_id,
        version=version,
        expected_size=expected_size,
        from_cache=False,
    )


def refresh_cached_firmware_template_candidate(candidate: FirmwareTemplateCandidate) -> FirmwareTemplateCandidate | None:
    if not candidate.from_cache or candidate.path is None or candidate.product_id is None or candidate.version is None:
        return None
    scheme = urlparse(candidate.source).scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    return download_firmware_template_to_cache(
        url=candidate.source,
        path=candidate.path,
        product_id=candidate.product_id,
        version=candidate.version,
        expected_size=candidate.expected_size,
    )


def _version_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts)


def _sorted_firmware_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        entries,
        key=lambda entry: (
            bool(entry.get("newest")),
            _version_key(str(entry.get("version") or "")),
            str(entry.get("version") or ""),
        ),
        reverse=True,
    )


def resolve_firmware_template_candidates(
    *,
    syap: str | int | None,
    firmware_template: Path | None,
    firmware_version: str | None = None,
    cache_dir: Path | None = None,
) -> Iterable[FirmwareTemplateCandidate]:
    normalized_syap = normalize_syap(syap)
    if firmware_template is not None:
        path = firmware_template.expanduser().resolve()
        try:
            with path.open("rb") as local:
                data = local.read(MAX_FIRMWARE_BYTES + 1)
        except OSError as exc:
            raise FlashAnalysisError(f"failed to read firmware template {path}: {exc}") from exc
        matching = [entry for entry in pinned_firmware_entries()
                    if entry["productID"] == normalized_syap
                    and (firmware_version is None or entry["version"] == firmware_version)
                    and entry["sha256"] == sha256_hex(data)]
        if not matching:
            raise FlashAnalysisError("local firmware template is not a reviewed image for this device")
        _verify_template(data, matching[0])
        yield FirmwareTemplateCandidate(
            data=data,
            source=str(path),
            path=path,
            product_id=None,
            version=firmware_version,
            expected_size=None,
            from_cache=False,
        )
        return

    resolved_cache_dir = (cache_dir or default_firmware_template_cache_root()).expanduser().resolve()
    catalog = load_apple_firmware_catalog(cache_dir=resolved_cache_dir)
    entries = [entry for entry in catalog if str(entry.get("productID") or "") == normalized_syap]
    if firmware_version is not None:
        entries = [entry for entry in entries if str(entry.get("version") or "") == firmware_version]
    if not entries:
        version_detail = "" if firmware_version is None else f" version {firmware_version}"
        raise FlashAnalysisError(f"Apple firmware catalog has no basebinary templates for syAP {normalized_syap}{version_detail}")
    for entry in _sorted_firmware_entries(entries):
        yield read_cached_or_download_template(entry, cache_dir=resolved_cache_dir)


def is_missing_key_error(message: str) -> bool:
    return "no candidate basebinary key validated checksum" in message or "no candidate keys were provided" in message
