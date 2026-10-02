#!/usr/bin/env python3
"""Build a signed DobbyVPN F-Droid repository from an existing GitHub Release."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import traceback
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import urlopen

APP_ID = "com.dobby.vpn"
ANDROID_SIGNER_SHA256 = "c3f0414a74012060d7c6aa3a3d9dac0aa13c1bd23b7512eefd860fb865e67933"
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
TAG_RE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
RELEASE_ASSET_NAMES = (
    "DobbyVPN-v{version}-android-provenance.json",
    "DobbyVPN-v{version}-sign.apk",
    "DobbyVPN-v{version}-unsign.apk",
    "version.txt",
    "dobbyVPN-linux.deb",
    "dobbyVPN-macos-aarch64.pkg",
    "dobbyVPN-macos-amd64.pkg",
    "dobbyVPN-windows-amd64.msi",
)
SITE_ROOT_FILES = {"repository.json", "index.html"}
SITE_ASSETS = {"assets/add-to-fdroid.svg", "assets/dobbyvpn.png", "assets/site.css"}


class RepoError(ValueError):
    """Invalid release input, signing identity, or generated repository."""


def emit_process_output(stdout: bytes, stderr: bytes) -> None:
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()


def run_capture(command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> bytes:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RepoError(f"could not start {command[0]}: {error}") from error
    emit_process_output(result.stdout, result.stderr)
    if result.returncode:
        raise RepoError(f"{command[0]} failed with exit code {result.returncode}")
    return result.stdout


def run_inherit(command: list[str], *, env: dict[str, str], cwd: Path) -> None:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise RepoError(f"could not start {command[0]}: {error}") from error
    if result.returncode:
        raise RepoError(f"{command[0]} failed with exit code {result.returncode}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_repository_config(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RepoError("repository.json must be valid UTF-8 JSON") from error
    expected = {"fingerprint", "key_alias", "repo_description", "repo_name", "repo_url"}
    if not isinstance(value, dict) or set(value) != expected:
        raise RepoError("repository.json has unexpected or missing fields")
    if not all(isinstance(item, str) and item.strip() for item in value.values()):
        raise RepoError("repository.json fields must be non-empty strings")
    fingerprint = value["fingerprint"].replace(":", "").lower()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise RepoError("repository.json fingerprint must be a SHA-256 certificate fingerprint")
    if not value["repo_url"].startswith("https://") or not value["repo_url"].rstrip("/").endswith("/fdroid/repo"):
        raise RepoError("repository.json repo_url must be the canonical HTTPS /fdroid/repo URL")
    if value["repo_url"].endswith("/"):
        raise RepoError("repository.json repo_url must not end in a slash")
    normalized = dict(value)
    normalized["fingerprint"] = fingerprint
    return normalized


def certificate_fingerprint(keytool: str, keystore: Path, alias: str, env: dict[str, str]) -> str:
    if not keystore.is_file() or keystore.is_symlink():
        raise RepoError("the configured repository keystore must be an existing regular file")
    if not env.get("FDROID_KEYSTORE_PASSWORD") or not env.get("FDROID_KEY_PASSWORD"):
        raise RepoError("FDROID_KEYSTORE_PASSWORD and FDROID_KEY_PASSWORD are required")
    raw = run_capture(
        [keytool, "-list", "-v", "-keystore", str(keystore), "-alias", alias,
         "-storepass:env", "FDROID_KEYSTORE_PASSWORD", "-keypass:env", "FDROID_KEY_PASSWORD"],
        env=env,
    ).decode("utf-8", errors="replace")
    matches = re.findall(r"(?im)^\s*SHA256:\s*([0-9a-f:]{64,95})\s*$", raw)
    if len(matches) != 1:
        raise RepoError("keytool did not report exactly one SHA-256 repository certificate fingerprint")
    fingerprint = matches[0].replace(":", "").lower()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise RepoError("keytool reported an invalid repository certificate fingerprint")
    return fingerprint


def verify_immutable_repository_key(
    config: dict[str, str], keystore: Path, alias: str, keytool: str, env: dict[str, str]
) -> str:
    if alias != config["key_alias"]:
        raise RepoError("repository key alias does not match repository.json")
    actual = certificate_fingerprint(keytool, keystore, alias, env)
    if actual != config["fingerprint"]:
        raise RepoError("repository keystore fingerprint differs from repository.json")
    return actual


def add_release_assets(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True, help="stable GitHub Release tag, e.g. v1.2.3")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-run-id", type=positive_integer, required=True)
    parser.add_argument("--release-run-number", type=positive_integer, required=True)
    parser.add_argument("--product-repo", type=Path, required=True, help="DobbyVPN checkout at the selected source SHA")
    parser.add_argument("--previous-url", help="public F-Droid repo URL to read the current signed index from; defaults to repository.json")


def load_product_validators(product_repo: Path) -> Any:
    product_repo = product_repo.resolve()
    scripts = product_repo / ".github" / "scripts"
    release_dir = scripts / "release"
    android_dir = scripts / "android"
    if not (release_dir / "release_provenance.py").is_file():
        raise RepoError("selected product checkout is missing release provenance validators")
    if not (android_dir / "verify_android_reproducibility.py").is_file():
        raise RepoError("selected product checkout is missing Android provenance validators")
    sys.path.insert(0, str(scripts))
    sys.path.insert(0, str(release_dir))
    sys.path.insert(0, str(android_dir))

    def import_file(name: str, path: Path) -> Any:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RepoError(f"cannot load product validator {path.name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    version_metadata = import_file("version_metadata", release_dir / "version_metadata.py")
    release_provenance = import_file("dobby_release_provenance", release_dir / "release_provenance.py")
    reproducibility = import_file("dobby_verify_android_reproducibility", android_dir / "verify_android_reproducibility.py")
    apk_source = import_file("dobby_verify_android_apk_source", android_dir / "verify_android_apk_source.py")
    return type("ProductValidators", (), {
        "version_metadata": version_metadata,
        "release_provenance": release_provenance,
        "reproducibility": reproducibility,
        "apk_source": apk_source,
    })


def product_repository_slug(product_repo: Path) -> str:
    raw = run_capture(["git", "-C", str(product_repo), "remote", "get-url", "origin"]).decode().strip()
    match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", raw)
    if not match:
        raise RepoError("DobbyVPN checkout origin must be a GitHub OWNER/REPOSITORY URL")
    return match.group(1)


def selected_product_metadata(product_repo: Path, source_sha: str, tag: str, validators: Any) -> tuple[str, int]:
    actual_sha = run_capture(["git", "-C", str(product_repo), "rev-parse", "HEAD"]).decode().strip()
    if actual_sha != source_sha:
        raise RepoError("product checkout HEAD does not match selected Release source SHA")
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise RepoError("source SHA must be a full lowercase 40-character Git SHA")
    try:
        version = validators.version_metadata.parse_version((product_repo / "VERSION").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RepoError(f"selected product VERSION is invalid: {error}") from error
    if tag != f"v{version.version_name}" or not TAG_RE.fullmatch(tag):
        raise RepoError("selected Release tag does not match the product VERSION")
    return version.version_name, version.android_version_code


def validate_selected_run(
    gh: str, github_repo: str, run_id: int, run_number: int, source_sha: str, env: dict[str, str]
) -> None:
    raw = run_capture(
        [gh, "run", "view", str(run_id), "--repo", github_repo,
         "--json", "databaseId,number,headSha,workflowName,status,conclusion"],
        env=env,
    )
    try:
        run = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RepoError("GitHub Actions did not return valid selected Release run metadata") from error
    expected = {
        "databaseId": run_id,
        "number": run_number,
        "headSha": source_sha,
        "workflowName": "Release",
        "status": "completed",
        "conclusion": "success",
    }
    if not isinstance(run, dict) or any(run.get(key) != value for key, value in expected.items()):
        raise RepoError("selected GitHub Actions run must be the successful Release for this source SHA")


def expected_release_assets(version: str) -> list[str]:
    return sorted(name.format(version=version) for name in RELEASE_ASSET_NAMES)


def add_repository_url(config: dict[str, str]) -> str:
    return f"https://fdroid.link/#{config['repo_url']}?fingerprint={config['fingerprint'].upper()}"


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RepoError(f"{label} is missing or invalid JSON") from error
    if not isinstance(document, dict):
        raise RepoError(f"{label} must be a JSON object")
    return document


def assert_release_files(directory: Path, expected_assets: Iterable[str]) -> None:
    expected = set(expected_assets) | {"release-provenance.json"}
    optional = {
        f"{name}.idsig" for name in expected if name.endswith("-sign.apk")
    }
    children = list(directory.iterdir())
    symlinks = [path.name for path in children if path.is_symlink()]
    actual = {path.name for path in children if path.is_file()}
    directories = [path.name for path in children if path.is_dir()]
    missing = expected - actual
    unexpected = actual - expected - optional
    if symlinks or directories or missing or unexpected:
        raise RepoError(
            "GitHub Release contains unexpected files: "
            f"expected required files {sorted(expected)} with optional {sorted(optional)}, "
            f"found files {sorted(actual)}, missing files {sorted(missing)}, "
            f"unexpected files {sorted(unexpected)}, directories {sorted(directories)}, "
            f"and symlinks {sorted(symlinks)}"
        )


def verify_apk_signer(apksigner: str, apk: Path, env: dict[str, str]) -> None:
    raw = run_capture([apksigner, "verify", "--print-certs", str(apk)], env=env)
    digests = [
        value.replace(b":", b"").decode("ascii").lower()
        for value in re.findall(rb"(?m)^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F:]+)$", raw)
    ]
    if digests != [ANDROID_SIGNER_SHA256]:
        raise RepoError("signed APK certificate does not match the pinned DobbyVPN production signer")


def verify_release_directory(
    directory: Path,
    *,
    tag: str,
    version: str,
    source_sha: str,
    run_id: int,
    run_number: int,
    version_code: int,
    validators: Any,
    apksigner: str,
    apkanalyzer: str,
    product_repo: Path,
    env: dict[str, str],
) -> Path:
    assets = expected_release_assets(version)
    assert_release_files(directory, assets)
    validators.release_provenance.verify_manifest(
        directory,
        tag=tag,
        version=version,
        source_sha=source_sha,
        release_run_id=run_id,
        release_run_number=run_number,
        android_version_code=version_code,
        assets=assets,
    )
    signed = directory / f"DobbyVPN-v{version}-sign.apk"
    unsigned = directory / f"DobbyVPN-v{version}-unsign.apk"
    android_provenance = directory / f"DobbyVPN-v{version}-android-provenance.json"
    validators.reproducibility.verify_publication_provenance(
        android_provenance,
        unsigned,
        signed,
        source_sha,
        version,
        version_code,
        ANDROID_SIGNER_SHA256,
    )
    validators.apk_source.verify_apk(
        apkanalyzer,
        signed,
        source_sha,
        product_repository_slug(product_repo),
        version,
        version_code,
    )
    verify_apk_signer(apksigner, signed, env)
    return signed


def download_release(
    gh: str, github_repo: str, tag: str, destination: Path, env: dict[str, str]
) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    run_inherit(
        [gh, "release", "download", tag, "--repo", github_repo, "--dir", str(destination)],
        env=env,
        cwd=destination.parent,
    )


def format_metadata(source: Path, target: Path, version: str, version_code: int) -> None:
    raw = source.read_text(encoding="utf-8")
    if re.search(r"(?m)^Builds\s*:", raw):
        raise RepoError("binary repository metadata must not contain Builds entries")
    for name, value in (("CurrentVersion", version), ("CurrentVersionCode", str(version_code))):
        pattern = re.compile(rf"(?m)^{re.escape(name)}:.*$")
        raw, count = pattern.subn(f"{name}: {value}", raw)
        if count != 1:
            raise RepoError(f"metadata must contain exactly one {name} field")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(raw, encoding="utf-8")


def write_fdroid_config(work: Path, config: dict[str, str], keystore: Path, alias: str) -> None:
    def yaml_string(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    data = "\n".join((
        f"repo_url: {yaml_string(config['repo_url'])}",
        f"repo_name: {yaml_string(config['repo_name'])}",
        f"repo_description: {yaml_string(config['repo_description'])}",
        'repo_icon: "dobbyvpn.png"',
        f"repo_keyalias: {yaml_string(alias)}",
        f"keystore: {yaml_string(str(keystore.resolve()))}",
        "keystorepass: {env: FDROID_KEYSTORE_PASSWORD}",
        "keypass: {env: FDROID_KEY_PASSWORD}",
        "repo_maxage: 0",
        "archive_older: 0",
        "",
    ))
    (work / "config.yml").write_text(data, encoding="utf-8")
    (work / "config.yml").chmod(0o600)


def stage_fdroid_repo_icon(work_dir: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "assets" / "site" / "dobbyvpn.png"
    shutil.copyfile(source, work_dir / "dobbyvpn.png")


def apk_manifest_value(apkanalyzer: str, apk: Path, field: str, env: dict[str, str]) -> str:
    return run_capture([apkanalyzer, "manifest", field, str(apk)], env=env).decode("utf-8").strip()


def previous_index_records(index_v2: Any, version_parser: Any) -> list[dict[str, Any]]:
    if not isinstance(index_v2, dict) or not isinstance(index_v2.get("packages"), dict):
        raise RepoError("previous F-Droid index has an incompatible package structure")
    package = index_v2["packages"].get(APP_ID)
    if package is None:
        return []
    if not isinstance(package, dict) or not isinstance(package.get("versions"), dict):
        raise RepoError("previous F-Droid index has malformed DobbyVPN version records")
    records: list[dict[str, Any]] = []
    seen_codes: set[int] = set()
    for version_key, version_record in package["versions"].items():
        if not isinstance(version_record, dict):
            raise RepoError("previous F-Droid index contains a malformed version record")
        manifest = version_record.get("manifest")
        file_record = version_record.get("file")
        if not isinstance(manifest, dict) or not isinstance(file_record, dict):
            raise RepoError("previous F-Droid version lacks manifest or file provenance")
        version = manifest.get("versionName")
        code = manifest.get("versionCode")
        name = file_record.get("name")
        digest = file_record.get("sha256")
        size = file_record.get("size")
        if (
            not isinstance(version, str)
            or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version)
            or not isinstance(code, int)
            or isinstance(code, bool)
            or code <= 0
            or not isinstance(name, str)
            or not isinstance(digest, str)
            or not FINGERPRINT_RE.fullmatch(digest)
            or version_key != digest
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise RepoError("previous F-Droid version has malformed identity or file hash metadata")
        try:
            parsed = version_parser.parse_version(version)
        except ValueError as error:
            raise RepoError(f"previous F-Droid version is not a supported stable release: {error}") from error
        if parsed.android_version_code != code:
            raise RepoError("previous F-Droid versionName and versionCode do not match")
        filename = PurePosixPath(name.lstrip("/")).name
        if name not in (filename, f"/{filename}") or filename != f"{APP_ID}_{code}.apk":
            raise RepoError("previous F-Droid APK path does not match its package and versionCode")
        if code in seen_codes:
            raise RepoError(f"previous F-Droid index contains duplicate versionCode {code}")
        seen_codes.add(code)
        records.append({"name": filename, "sha256": digest, "size": size, "version": version, "version_code": code})
    return sorted(records, key=lambda item: item["version_code"], reverse=True)


@contextmanager
def fdroid_index_client():
    """Configure the standalone index verifier without loading private config."""
    try:
        from fdroidserver import common, index as fdroid_index
    except ImportError as error:
        raise RepoError("fdroidserver Python package is required to verify signed indexes") from error
    jarsigner = shutil.which("jarsigner")
    if not jarsigner:
        raise RepoError("JDK jarsigner is required to verify repository signatures")
    previous_config = common.config
    with tempfile.TemporaryDirectory(prefix="dobby-fdroid-index-") as cache:
        common.config = {"jarsigner": jarsigner, "cachedir": cache}
        try:
            yield fdroid_index
        finally:
            common.config = previous_config


def download_previous_index(previous_url: str, fingerprint: str) -> Any:
    base_url = previous_url.rstrip("/")
    if urlsplit(base_url).scheme != "https":
        raise RepoError("previous repository URL must use HTTPS")
    separator = "&" if "?" in base_url else "?"
    verified_url = f"{base_url}{separator}fingerprint={fingerprint.upper()}"
    try:
        with fdroid_index_client() as fdroid_index:
            index_v2, _ = fdroid_index.download_repo_index_v2(verified_url, verify_fingerprint=True)
    except Exception as error:
        raise RepoError(f"fdroidserver could not verify the previous repository index: {error}") from error
    if not isinstance(index_v2, dict):
        raise RepoError("previous repository did not return an F-Droid v2 index")
    return index_v2


def _is_unpublished_entry_jar_error(error: RepoError, previous_url: str) -> bool:
    parsed_url = urlsplit(previous_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        return False
    entry_url = urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        f"{parsed_url.path.rstrip('/')}/entry.jar",
        "",
        "",
    ))
    try:
        import requests
        from urllib3.exceptions import MaxRetryError, SSLError as Urllib3SSLError
    except ImportError:
        return False

    cause = error.__cause__
    if isinstance(cause, requests.exceptions.HTTPError):
        response = cause.response
        return (
            response is not None
            and response.status_code == 404
            and response.url == entry_url
        )
    if not isinstance(cause, requests.exceptions.SSLError):
        return False
    request = cause.request
    if request is None or request.url != entry_url or len(cause.args) != 1:
        return False
    retry_error = cause.args[0]
    if not isinstance(retry_error, MaxRetryError):
        return False
    transport_error = retry_error.reason
    if not isinstance(transport_error, Urllib3SSLError) or len(transport_error.args) != 1:
        return False
    certificate_error = transport_error.args[0]
    return (
        isinstance(certificate_error, ssl.SSLCertVerificationError)
        and getattr(certificate_error, "verify_code", None) == 62
    )


def _slurped_api_collection(raw: bytes, description: str) -> list[Any]:
    try:
        pages = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RepoError(f"GitHub {description} API did not return valid JSON") from error
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise RepoError(f"GitHub {description} API response is malformed")
    return [record for page in pages for record in page]


def _deployment_job_url(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"https://github\.com/DobbyVPN/DobbyVPN/actions/runs/([0-9]+)/job/([0-9]+)", value
    )
    if not match:
        return None
    return match.group(1), match.group(2)


def _history_proves_unpublished(
    gh: str, github_repo: str, env: dict[str, str]
) -> bool:
    raw = run_capture([
        gh, "api", "--paginate", "--slurp",
        f"repos/{github_repo}/deployments?environment=github-pages&per_page=100",
    ], env=env)
    deployments = _slurped_api_collection(raw, "deployment history")
    if not deployments:
        return True

    active_states = {"waiting", "queued", "pending", "in_progress"}
    current_run_id = env.get("GITHUB_RUN_ID")
    for deployment in deployments:
        if not isinstance(deployment, dict) or type(deployment.get("id")) is not int:
            return False
        raw = run_capture([
            gh, "api", "--paginate", "--slurp",
            f"repos/{github_repo}/deployments/{deployment['id']}/statuses?per_page=100",
        ], env=env)
        statuses = _slurped_api_collection(raw, "deployment statuses")
        if not statuses or any(not isinstance(row, dict) for row in statuses):
            return False

        urls = {row.get("log_url") for row in statuses}
        if len(urls) != 1:
            return False
        job_url = _deployment_job_url(next(iter(urls)))
        if job_url is None:
            return False
        run_id, job_id = job_url
        states = [row.get("state") for row in statuses]
        if current_run_id and run_id == current_run_id and all(state in active_states for state in states):
            continue
        if any(state == "success" for state in states):
            return False

        raw = run_capture([gh, "api", f"repos/{github_repo}/actions/jobs/{job_id}"], env=env)
        try:
            job = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RepoError("GitHub deployment job API did not return valid JSON") from error
        if not isinstance(job, dict) or str(job.get("run_id")) != run_id or job.get("status") != "completed":
            return False
        steps = job.get("steps")
        if not isinstance(steps, list):
            return False
        deploy_steps = [step for step in steps if isinstance(step, dict) and step.get("name") == "Deploy repository"]
        if len(deploy_steps) != 1 or deploy_steps[0].get("conclusion") != "skipped":
            return False
    return True


def verify_initialization_target(
    gh: str, github_repo: str, previous_url: str, fingerprint: str, env: dict[str, str]
) -> None:
    """Initialize only after an empty signed index or a proven Pages bootstrap absence."""
    if github_repo != "DobbyVPN/DobbyVPN":
        raise RepoError("Pages must be hosted on DobbyVPN/DobbyVPN")
    raw = run_capture([gh, "api", f"repos/{github_repo}/pages"], env=env)
    try:
        pages = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RepoError("GitHub Pages API did not return valid JSON") from error
    if not isinstance(pages, dict) or "status" not in pages:
        raise RepoError("GitHub Pages API response has no status field")
    status = pages["status"]
    if status not in (None, "built"):
        raise RepoError(f"GitHub Pages status is {status!r}; refusing repository initialization")
    history_error: RepoError | None = None
    try:
        first_activation = _history_proves_unpublished(gh, github_repo, env)
    except RepoError as error:
        # Incomplete or malformed native history cannot authorize activation;
        # only a verified empty index can still authorize initialization.
        first_activation = False
        history_error = error
    try:
        index_v2 = download_previous_index(previous_url, fingerprint)
    except RepoError as error:
        if status is None and first_activation and _is_unpublished_entry_jar_error(error, previous_url):
            return
        if history_error is not None:
            raise RepoError(f"{history_error}; {error}") from error
        raise
    if not isinstance(index_v2, dict):
        raise RepoError("existing public repository has a malformed signed index")
    packages = index_v2.get("packages")
    if not isinstance(packages, dict):
        raise RepoError("existing public repository has a malformed signed package index")
    if packages:
        raise RepoError("existing public repository contains packages; refusing empty initialization")


def download_prior_apk(url: str, target: Path) -> None:
    try:
        with urlopen(url) as response, target.open("wb") as output:
            if urlsplit(response.geturl()).scheme != "https":
                raise RepoError("previous APK download redirected away from HTTPS")
            shutil.copyfileobj(response, output)
    except (HTTPError, URLError, OSError) as error:
        target.unlink(missing_ok=True)
        raise RepoError(f"could not download a previously indexed APK: {error}") from error


def validate_previous_versions(
    index_v2: Any,
    *,
    previous_url: str,
    selected_version_code: int,
    selected_apk: Path,
    repo_dir: Path,
    work: Path,
    version_parser: Any,
    apksigner: str,
    apkanalyzer: str,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    records = previous_index_records(index_v2, version_parser)
    if any(record["version_code"] > selected_version_code for record in records):
        raise RepoError("previous F-Droid repository contains a newer version than the selected release")
    base_url = previous_url.rstrip("/") + "/"
    for record in records:
        target = work / record["name"]
        download_prior_apk(urljoin(base_url, quote(record["name"])), target)
        if target.stat().st_size != record["size"] or sha256_file(target) != record["sha256"]:
            raise RepoError(f"previous APK hash or size differs from its signed index: {record['name']}")
        package = apk_manifest_value(apkanalyzer, target, "application-id", env)
        version = apk_manifest_value(apkanalyzer, target, "version-name", env)
        code = apk_manifest_value(apkanalyzer, target, "version-code", env)
        if package != APP_ID or version != record["version"] or code != str(record["version_code"]):
            raise RepoError(f"previous APK identity differs from its signed index: {record['name']}")
        verify_apk_signer(apksigner, target, env)
        record["apk"] = target
    same_code = [record for record in records if record["version_code"] == selected_version_code]
    if same_code:
        if len(same_code) != 1 or sha256_file(same_code[0]["apk"]) != sha256_file(selected_apk):
            raise RepoError("selected versionCode already exists with different release APK bytes")
    prior = [record for record in records if record["version_code"] < selected_version_code]
    for record in prior[:2]:
        shutil.copyfile(record["apk"], repo_dir / record["name"])
    return prior

def list_repository_apks(repo_dir: Path) -> list[Path]:
    apks = sorted(repo_dir.glob("*.apk"))
    for path in apks:
        if path.is_symlink() or not re.fullmatch(rf"{re.escape(APP_ID)}_[1-9][0-9]*\.apk", path.name):
            raise RepoError(f"unexpected APK in repository: {path.name}")
    return apks


def _walk_file_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if isinstance(value.get("name"), str) and isinstance(value.get("sha256"), str) and isinstance(value.get("size"), int):
            yield value
        for item in value.values():
            yield from _walk_file_records(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_file_records(item)


def verify_index_records(index_v2: dict[str, Any], repo_dir: Path) -> list[dict[str, Any]]:
    packages = index_v2.get("packages")
    if not isinstance(packages, dict):
        raise RepoError("index-v2 has an incompatible packages structure")
    if set(packages) - {APP_ID}:
        raise RepoError("index-v2 contains an unexpected application package")
    package = packages.get(APP_ID)
    if package is None:
        versions: dict[str, Any] = {}
    elif isinstance(package, dict) and isinstance(package.get("versions"), dict):
        versions = package["versions"]
    else:
        raise RepoError("index-v2 has malformed DobbyVPN version records")
    records = []
    for version_key, version_record in versions.items():
        if not isinstance(version_record, dict):
            raise RepoError("index-v2 contains a malformed version record")
        manifest = version_record.get("manifest")
        file_record = version_record.get("file")
        if not isinstance(manifest, dict) or not isinstance(file_record, dict):
            raise RepoError("index-v2 version record lacks manifest or file metadata")
        version = manifest.get("versionName")
        code = manifest.get("versionCode")
        raw_name = file_record.get("name")
        digest = file_record.get("sha256")
        size = file_record.get("size")
        if (
            not isinstance(version, str)
            or not isinstance(code, int)
            or isinstance(code, bool)
            or code <= 0
            or not isinstance(raw_name, str)
            or not isinstance(digest, str)
            or not FINGERPRINT_RE.fullmatch(digest)
            or version_key != digest
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            raise RepoError("index-v2 contains malformed DobbyVPN version or file metadata")
        name = PurePosixPath(raw_name.lstrip("/")).name
        if raw_name not in (name, f"/{name}") or name != f"{APP_ID}_{code}.apk":
            raise RepoError(f"index-v2 APK path does not match its package and versionCode: {raw_name}")
        path = repo_dir / name
        if not path.is_file():
            raise RepoError(f"index-v2 refers to missing APK: {name}")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise RepoError(f"index-v2 APK hash or size mismatch: {name}")
        records.append({
            "name": name,
            "sha256": digest,
            "size": size,
            "version": version,
            "version_code": code,
        })
    actual = {path.name for path in list_repository_apks(repo_dir)}
    indexed = {record["name"] for record in records}
    if len(records) != len(indexed):
        raise RepoError("index-v2 contains duplicate DobbyVPN APK records")
    if actual != indexed:
        raise RepoError(f"repository APK set does not match index-v2: actual {sorted(actual)}, indexed {sorted(indexed)}")
    if len(records) > 3:
        raise RepoError("F-Droid index contains more than the latest three DobbyVPN versions")
    return sorted(records, key=lambda item: item["version_code"], reverse=True)


def verify_index_version_consistency(index_v1: dict[str, Any], index_v2: dict[str, Any]) -> None:
    """Require both signed index formats to describe the same APK versions."""
    packages_v1 = index_v1.get("packages")
    packages_v2 = index_v2.get("packages")
    if not isinstance(packages_v1, dict) or not isinstance(packages_v2, dict):
        raise RepoError("F-Droid index package metadata is malformed")
    if set(packages_v1) != set(packages_v2):
        raise RepoError("index-v1 and index-v2 package sets differ")
    if set(packages_v1) - {APP_ID}:
        raise RepoError("F-Droid index contains an unexpected application package")

    versions_v1: dict[int, tuple[str, str, int, str]] = {}
    app_versions_v1 = packages_v1.get(APP_ID, [])
    if not isinstance(app_versions_v1, list):
        raise RepoError("index-v1 DobbyVPN package versions are malformed")
    for version in app_versions_v1:
        if not isinstance(version, dict):
            raise RepoError("index-v1 contains a malformed DobbyVPN version")
        code = version.get("versionCode")
        values = (version.get("versionName"), version.get("apkName"), version.get("size"), version.get("hash"))
        if (
            not isinstance(code, int)
            or isinstance(code, bool)
            or code <= 0
            or not isinstance(values[0], str)
            or not isinstance(values[1], str)
            or not isinstance(values[2], int)
            or isinstance(values[2], bool)
            or values[2] <= 0
            or not isinstance(values[3], str)
            or not FINGERPRINT_RE.fullmatch(values[3])
        ):
            raise RepoError("index-v1 contains malformed DobbyVPN version or file metadata")
        if code in versions_v1:
            raise RepoError("index-v1 contains duplicate DobbyVPN versionCode records")
        versions_v1[code] = (values[0], values[1], values[2], values[3])

    versions_v2: dict[int, tuple[str, str, int, str]] = {}
    package_v2 = packages_v2.get(APP_ID)
    if package_v2 is not None:
        if not isinstance(package_v2, dict) or not isinstance(package_v2.get("versions"), dict):
            raise RepoError("index-v2 DobbyVPN package versions are malformed")
        for version in package_v2["versions"].values():
            manifest = version.get("manifest") if isinstance(version, dict) else None
            file_record = version.get("file") if isinstance(version, dict) else None
            if not isinstance(manifest, dict) or not isinstance(file_record, dict):
                raise RepoError("index-v2 contains a malformed DobbyVPN version")
            code = manifest.get("versionCode")
            name = manifest.get("versionName")
            filename = file_record.get("name")
            digest = file_record.get("sha256")
            size = file_record.get("size")
            if (
                not isinstance(code, int)
                or isinstance(code, bool)
                or code <= 0
                or not isinstance(name, str)
                or not isinstance(filename, str)
                or not isinstance(digest, str)
                or not FINGERPRINT_RE.fullmatch(digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
            ):
                raise RepoError("index-v2 contains malformed DobbyVPN version or file metadata")
            filename = PurePosixPath(filename.lstrip("/")).name
            if code in versions_v2:
                raise RepoError("index-v2 contains duplicate DobbyVPN versionCode records")
            versions_v2[code] = (name, filename, size, digest)
    if versions_v1 != versions_v2:
        raise RepoError("index-v1 and index-v2 version or APK hash metadata differ")


def verify_fdroid_indexes(fdroid_root: Path, expected_fingerprint: str) -> list[dict[str, Any]]:
    repo_dir = fdroid_root / "repo"
    index_jar = repo_dir / "index.jar"
    v1_jar = repo_dir / "index-v1.jar"
    v1_json = repo_dir / "index-v1.json"
    v2_json = repo_dir / "index-v2.json"
    entry_jar = repo_dir / "entry.jar"
    entry_json = repo_dir / "entry.json"
    required = (index_jar, v1_jar, v1_json, v2_json, entry_jar, entry_json, repo_dir / "icons" / "dobbyvpn.png")
    if any(not item.is_file() for item in required):
        raise RepoError("fdroid update did not produce all signed index files")
    try:
        with fdroid_index_client() as fdroid_index:
            # F-Droid's v1 format requires its legacy JAR algorithms. The v2
            # entry below is verified with the current algorithm policy.
            jar_v1, _, fingerprint_v1 = fdroid_index.get_index_from_jar(
                str(v1_jar), fingerprint=expected_fingerprint, allow_deprecated=True
            )
            jar_entry, _, fingerprint_entry = fdroid_index.get_index_from_jar(str(entry_jar), fingerprint=expected_fingerprint)
    except Exception as error:
        raise RepoError(f"fdroidserver rejected a signed repository index: {error}") from error
    if fingerprint_v1.replace(":", "").lower() != expected_fingerprint:
        raise RepoError("index-v1.jar was signed with an unexpected repository key")
    if fingerprint_entry.replace(":", "").lower() != expected_fingerprint:
        raise RepoError("entry.jar was signed with an unexpected repository key")
    if jar_v1 != json.loads(v1_json.read_text(encoding="utf-8")):
        raise RepoError("index-v1.json differs from the signed index-v1.jar contents")
    if jar_entry != json.loads(entry_json.read_text(encoding="utf-8")):
        raise RepoError("entry.json differs from the signed entry.jar contents")
    entry_records = list(_walk_file_records(jar_entry))
    index_v2_records = [record for record in entry_records if PurePosixPath(record["name"]).name == "index-v2.json"]
    if len(index_v2_records) != 1:
        raise RepoError("signed F-Droid entry does not contain exactly one index-v2 record")
    for record in entry_records:
        name = record["name"].lstrip("/")
        if name != "index-v2.json" and not re.fullmatch(r"diff/[0-9]+\.json", name):
            raise RepoError(f"signed F-Droid entry contains an unexpected file: {name}")
        path = repo_dir / name
        if not path.is_file() or path.is_symlink():
            raise RepoError(f"signed F-Droid entry refers to a missing file: {name}")
        if path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
            raise RepoError(f"signed F-Droid entry has an inconsistent file hash or size: {name}")
    v2_bytes = v2_json.read_bytes()
    record = index_v2_records[0]
    if record["size"] != len(v2_bytes) or record["sha256"] != hashlib.sha256(v2_bytes).hexdigest():
        raise RepoError("signed F-Droid entry has an inconsistent index-v2 hash or size")
    index_v1 = json.loads(v1_json.read_text(encoding="utf-8"))
    index_v2 = json.loads(v2_bytes.decode("utf-8"))
    verify_index_version_consistency(index_v1, index_v2)
    return verify_index_records(index_v2, repo_dir)


def validate_public_tree(root: Path, expected_fingerprint: str) -> None:
    if root.is_symlink() or not root.is_dir():
        raise RepoError("public output must be a regular directory")
    config_path = root / "repository.json"
    config = load_repository_config(config_path)
    if config["fingerprint"] != expected_fingerprint:
        raise RepoError("public repository.json fingerprint differs from the signing key")
    allowed_files = SITE_ROOT_FILES | SITE_ASSETS
    allowed_files.update({
        "fdroid/repo/entry.jar",
        "fdroid/repo/index.jar",
        "fdroid/repo/index.html",
        "fdroid/repo/index.css",
        "fdroid/repo/index.png",
        "fdroid/repo/icons/dobbyvpn.png",
    })
    allowed_files.add("fdroid/repo/entry.json")
    allowed_files.add("fdroid/repo/entry.json.asc")
    allowed_files.add("fdroid/repo/index.jar")
    allowed_files.add("fdroid/repo/index-v1.jar")
    allowed_files.add("fdroid/repo/index-v1.json")
    allowed_files.add("fdroid/repo/index-v1.json.asc")
    allowed_files.add("fdroid/repo/index-v2.json")
    allowed_files.add("fdroid/repo/index-v2.json.asc")

    allowed_directories = {"assets", "fdroid", "fdroid/repo", "fdroid/repo/diff"}
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise RepoError(f"public tree contains a symlink: {relative}")
        if path.is_file():
            actual_files.add(relative)
        elif path.is_dir():
            if relative not in allowed_directories and not re.fullmatch(r"fdroid/repo/icons(?:-[0-9]+)?", relative):
                raise RepoError(f"public tree contains an unexpected directory: {relative}")
            continue
        else:
            raise RepoError(f"public tree contains an unsupported filesystem entry: {relative}")
    for name in actual_files:
        if name in allowed_files:
            continue
        if re.fullmatch(r"fdroid/repo/com\.dobby\.vpn_[1-9][0-9]*\.apk", name):
            continue
        if re.fullmatch(r"fdroid/repo/diff/[0-9]+\.json", name):
            continue
        if re.fullmatch(r"fdroid/repo/icons(?:-[0-9]+)?/[A-Za-z0-9._-]+\.png", name):
            continue
        raise RepoError(f"public tree contains an unexpected file: {name}")
    missing = (
        SITE_ROOT_FILES
        | SITE_ASSETS
        | {
            "fdroid/repo/entry.jar",
            "fdroid/repo/entry.json",
            "fdroid/repo/index.jar",
            "fdroid/repo/index-v1.jar",
            "fdroid/repo/index-v1.json",
            "fdroid/repo/index-v2.json",
            "fdroid/repo/icons/dobbyvpn.png",
        }
    ) - actual_files
    if missing:
        raise RepoError(f"public tree is missing required public files: {sorted(missing)}")
    if any(re.search(r"(?i)(?:\.env|\.jks|\.keystore|\.p12|private|config\.yml)$", name) for name in actual_files):
        raise RepoError("public tree contains private configuration or key material")


def write_qr(add_url: str, target: Path) -> None:
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError as error:
        raise RepoError("qrcode with its SVG factory is required to generate the repository QR code") from error
    qr = qrcode.QRCode(border=4, box_size=10, image_factory=SvgPathImage)
    qr.add_data(add_url)
    qr.make(fit=True)
    qr.make_image().save(target)


def stage_site(root: Path, config: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "repository.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    assets = root / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    source_assets = Path(__file__).resolve().parents[1] / "assets" / "site"
    template = (source_assets / "index.html").read_text(encoding="utf-8")
    add_url = add_repository_url(config)
    template = template.replace("{{ADD_REPO_URL}}", html.escape(add_url, quote=True))
    template = template.replace("{{REPO_URL}}", html.escape(config["repo_url"], quote=True))
    template = template.replace("{{FINGERPRINT}}", html.escape(config["fingerprint"].upper(), quote=True))
    if "{{" in template or "}}" in template:
        raise RepoError("site template contains an unresolved placeholder")
    (root / "index.html").write_text(template, encoding="utf-8")
    shutil.copyfile(source_assets / "site.css", assets / "site.css")
    shutil.copyfile(source_assets / "dobbyvpn.png", assets / "dobbyvpn.png")
    write_qr(add_url, assets / "add-to-fdroid.svg")


def ensure_empty_output(output: Path) -> None:
    if output.is_symlink():
        raise RepoError("public output path must not be a symlink")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise RepoError("public output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)


def build_repository(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = load_repository_config(args.repository_config)
    env = os.environ.copy()
    verify_immutable_repository_key(config, args.keystore, args.alias, args.keytool, env)

    if args.initialize:
        if any(getattr(args, item, None) for item in ("tag", "source_sha", "release_run_id", "release_run_number", "product_repo")):
            raise RepoError("--initialize cannot be combined with Release inputs")
        github_repo = args.github_repo or env.get("GITHUB_REPOSITORY", "")
        verify_initialization_target(args.gh, github_repo, config["repo_url"], config["fingerprint"], env)
        ensure_empty_output(args.output)
        work_env = env
        with tempfile.TemporaryDirectory(prefix="dobby-fdroid-initialize-") as raw_work:
            work = Path(raw_work)
            write_fdroid_config(work, config, args.keystore, args.alias)
            (work / "metadata").mkdir()
            (work / "repo").mkdir()
            stage_fdroid_repo_icon(work)
            run_inherit([args.fdroid, "update"], env=work_env, cwd=work)
            public_fdroid = args.output / "fdroid"
            public_fdroid.mkdir()
            shutil.copytree(
                work / "repo", public_fdroid / "repo",
                ignore=shutil.ignore_patterns("status", "index.xml"),
            )
            stage_site(args.output, config)
        verify_fdroid_indexes(args.output / "fdroid", config["fingerprint"])
        validate_public_tree(args.output, config["fingerprint"])
        return

    ensure_empty_output(args.output)
    validators = load_product_validators(args.product_repo)
    version, version_code = selected_product_metadata(args.product_repo, args.source_sha, args.tag, validators)
    github_repo = product_repository_slug(args.product_repo)
    validate_selected_run(args.gh, github_repo, args.release_run_id, args.release_run_number, args.source_sha, env)

    with tempfile.TemporaryDirectory(prefix="dobby-fdroid-build-") as raw_work:
        work = Path(raw_work)
        release_dir = work / "selected-release"
        download_release(args.gh, github_repo, args.tag, release_dir, env)
        signed = verify_release_directory(
            release_dir,
            tag=args.tag,
            version=version,
            source_sha=args.source_sha,
            run_id=args.release_run_id,
            run_number=args.release_run_number,
            version_code=version_code,
            validators=validators,
            apksigner=args.apksigner,
            apkanalyzer=args.apkanalyzer,
            product_repo=args.product_repo,
            env=env,
        )
        previous_url = args.previous_url or config["repo_url"]
        previous_index = download_previous_index(previous_url, config["fingerprint"])
        repo_dir = work / "repo"
        repo_dir.mkdir()
        stage_fdroid_repo_icon(work)
        validate_previous_versions(
            previous_index,
            previous_url=previous_url,
            selected_version_code=version_code,
            selected_apk=signed,
            repo_dir=repo_dir,
            work=work,
            version_parser=validators.version_metadata,
            apksigner=args.apksigner,
            apkanalyzer=args.apkanalyzer,
            env=env,
        )
        (work / "metadata").mkdir()
        format_metadata(repo_root / "metadata" / f"{APP_ID}.yml", work / "metadata" / f"{APP_ID}.yml", version, version_code)
        current_apk = repo_dir / f"{APP_ID}_{version_code}.apk"
        shutil.copyfile(signed, current_apk)
        if sha256_file(current_apk) != sha256_file(signed):
            raise RepoError("staged APK bytes differ from the selected GitHub Release APK")
        public_fdroid = args.output / "fdroid"
        public_fdroid.mkdir()
        write_fdroid_config(work, config, args.keystore, args.alias)
        run_inherit([args.fdroid, "update"], env=env, cwd=work)
        shutil.copytree(
            repo_dir, public_fdroid / "repo",
            ignore=shutil.ignore_patterns("status", "index.xml"),
        )
        stage_site(args.output, config)
        verify_fdroid_indexes(public_fdroid, config["fingerprint"])
        validate_public_tree(args.output, config["fingerprint"])
        args.android_version_code = version_code
        args.current_apk_sha256 = sha256_file(current_apk)


def positive_integer(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="empty directory for the generated public Pages tree")
    parser.add_argument("--repository-config", type=Path, default=Path(__file__).resolve().parents[1] / "repository.json")
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--fdroid", default="fdroid")
    parser.add_argument("--keytool", default="keytool")
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--apkanalyzer", default="apkanalyzer")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--github-repo", help="caller product OWNER/REPOSITORY for Pages initialization; defaults to GITHUB_REPOSITORY")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initialize", action="store_true", help="create an empty signed repository for infrastructure preparation")
    mode.add_argument("--release", action="store_true", help="build from the selected existing signed GitHub Release")
    # Keep release flags out of the initialize CLI to make accidental APK
    # publication from the infrastructure-preparation path impossible.
    args, remaining = parser.parse_known_args(argv)
    try:
        if args.release:
            release_parser = argparse.ArgumentParser(add_help=False)
            add_release_assets(release_parser)
            release_args = release_parser.parse_args(remaining)
            vars(args).update(vars(release_args))
        elif remaining:
            parser.error("unexpected arguments for --initialize")
        build_repository(args)
    except (OSError, RepoError, subprocess.SubprocessError) as error:
        print(f"F-Droid repository build failed: {error}", file=sys.stderr)
        traceback.print_exc()
        return 1
    print(f"Public F-Droid repository tree is ready: {args.output}")
    if args.release:
        print(f"version_code={args.android_version_code}")
        print(f"current_apk_sha256={args.current_apk_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
