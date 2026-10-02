#!/usr/bin/env python3
"""Verify the deployed F-Droid index, APKs, Add-to-F-Droid link, and QR code."""
from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_repo

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class _SiteAttributes(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: set[str] = set()
        self.sources: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("href") is not None:
            self.hrefs.add(values["href"])
        if values.get("src") is not None:
            self.sources.add(values["src"])


def fetch_https(url: str) -> tuple[bytes, str, str]:
    try:
        with urlopen(url) as response:
            final_url = response.geturl()
            if urlsplit(final_url).scheme != "https":
                raise build_repo.RepoError(f"public endpoint redirected away from HTTPS: {url}")
            status = getattr(response, "status", 200)
            if status != 200:
                raise build_repo.RepoError(f"public endpoint returned HTTP {status}: {url}")
            content_type = response.headers.get("Content-Type", "")
            return response.read(), final_url, content_type
    except (HTTPError, URLError, OSError) as error:
        raise build_repo.RepoError(f"could not read public endpoint {url}: {error}") from error


def verify_site(config: dict[str, str], repository_config_path: Path) -> str:
    parsed = urlsplit(config["repo_url"])
    site_url = f"{parsed.scheme}://{parsed.netloc}/"
    add_url = build_repo.add_repository_url(config)
    html_bytes, final_url, content_type = fetch_https(site_url)
    if urlsplit(final_url).netloc != parsed.netloc or "text/html" not in content_type.lower():
        raise build_repo.RepoError("repository website did not return its HTML page over the configured HTTPS host")
    html = html_bytes.decode("utf-8")
    attributes = _SiteAttributes()
    attributes.feed(html)
    if add_url not in attributes.hrefs or "/assets/add-to-fdroid.svg" not in attributes.sources:
        raise build_repo.RepoError("deployed site is missing the expected Add-to-F-Droid URL or QR image")
    if config["repo_url"] not in html or config["fingerprint"].upper() not in html:
        raise build_repo.RepoError("deployed site does not show the configured repository URL and fingerprint")

    remote_config, _, _ = fetch_https(site_url.rstrip("/") + "/repository.json")
    local_config = json.loads(repository_config_path.read_text(encoding="utf-8"))
    if json.loads(remote_config.decode("utf-8")) != local_config:
        raise build_repo.RepoError("deployed repository.json differs from the configured repository identity")

    remote_qr, _, content_type = fetch_https(site_url.rstrip("/") + "/assets/add-to-fdroid.svg")
    if "image/svg+xml" not in content_type.lower():
        raise build_repo.RepoError("deployed Add-to-F-Droid QR is not served as SVG")
    with tempfile.TemporaryDirectory(prefix="dobby-fdroid-qr-check-") as temporary:
        expected_path = Path(temporary) / "add-to-fdroid.svg"
        build_repo.write_qr(add_url, expected_path)
        if remote_qr != expected_path.read_bytes():
            raise build_repo.RepoError("deployed QR code does not encode the configured Add-to-F-Droid URL")
    return site_url


def verify_live_repository(args: argparse.Namespace) -> None:
    config = build_repo.load_repository_config(args.repository_config)
    site_url = verify_site(config, args.repository_config)
    index_v2 = build_repo.download_previous_index(args.repo_url or config["repo_url"], config["fingerprint"])
    packages = index_v2.get("packages")
    if not isinstance(packages, dict):
        raise build_repo.RepoError("deployed F-Droid index has an incompatible package structure")
    if args.expect_empty:
        if packages:
            raise build_repo.RepoError("infrastructure initialization index unexpectedly contains app packages")
        print(f"Verified empty signed F-Droid repository at {config['repo_url']} and site {site_url}")
        return

    if not isinstance(args.product_repo, Path):
        raise build_repo.RepoError("--product-repo is required when verifying an app release")
    validators = build_repo.load_product_validators(args.product_repo)
    actual_sha = build_repo.run_capture(["git", "-C", str(args.product_repo), "rev-parse", "HEAD"]).decode().strip()
    if actual_sha != args.source_sha:
        raise build_repo.RepoError("post-deploy product checkout HEAD differs from the selected source SHA")
    selected_version = validators.version_metadata.parse_version((args.product_repo / "VERSION").read_text(encoding="utf-8"))
    if (
        args.version != selected_version.version_name
        or args.version_code != selected_version.android_version_code
        or args.tag != f"v{args.version}"
    ):
        raise build_repo.RepoError("post-deploy expected version does not match the selected product source")
    if not SHA256_RE.fullmatch(args.apk_sha256):
        raise build_repo.RepoError("--apk-sha256 must be a lowercase SHA-256 digest")

    records = build_repo.previous_index_records(index_v2, validators.version_metadata)
    if not records or len(records) > 3:
        raise build_repo.RepoError("deployed repository must contain one to three signed DobbyVPN versions")
    newest = records[0]
    if newest["version"] != args.version or newest["version_code"] != args.version_code or newest["sha256"] != args.apk_sha256:
        raise build_repo.RepoError("deployed signed index does not point to the selected release as its newest version")

    base_url = (args.repo_url or config["repo_url"]).rstrip("/") + "/"
    with tempfile.TemporaryDirectory(prefix="dobby-fdroid-public-check-") as temporary:
        for record in records:
            apk = Path(temporary) / record["name"]
            build_repo.download_prior_apk(base_url + record["name"], apk)
            if apk.stat().st_size != record["size"] or build_repo.sha256_file(apk) != record["sha256"]:
                raise build_repo.RepoError(f"deployed APK differs from its signed F-Droid index: {record['name']}")
            package = build_repo.apk_manifest_value(args.apkanalyzer, apk, "application-id", os.environ.copy())
            version = build_repo.apk_manifest_value(args.apkanalyzer, apk, "version-name", os.environ.copy())
            code = build_repo.apk_manifest_value(args.apkanalyzer, apk, "version-code", os.environ.copy())
            if package != build_repo.APP_ID or version != record["version"] or code != str(record["version_code"]):
                raise build_repo.RepoError(f"deployed APK identity differs from its signed index: {record['name']}")
            build_repo.verify_apk_signer(args.apksigner, apk, os.environ.copy())
    print(
        f"Verified deployed F-Droid index, {len(records)} signed APK version(s), production signer, "
        f"and Add-to-F-Droid page at {site_url}"
    )


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
    parser.add_argument("--repository-config", type=Path, default=Path(__file__).resolve().parents[1] / "repository.json")
    parser.add_argument("--repo-url", help="public repo URL to verify; defaults to repository.json")
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--apkanalyzer", default="apkanalyzer")
    expectation = parser.add_mutually_exclusive_group(required=True)
    expectation.add_argument("--expect-empty", action="store_true", help="verify a signed empty repository")
    expectation.add_argument("--expect-version", help="expected selected stable version, e.g. 1.2.3")
    parser.add_argument("--tag")
    parser.add_argument("--version-code", type=positive_integer)
    parser.add_argument("--apk-sha256")
    parser.add_argument("--source-sha")
    parser.add_argument("--product-repo", type=Path)
    args = parser.parse_args(argv)
    if not args.expect_empty and not all((args.tag, args.version_code, args.apk_sha256, args.source_sha, args.product_repo)):
        parser.error("app verification requires --tag, --version-code, --apk-sha256, --source-sha, and --product-repo")
    args.version = args.expect_version
    try:
        verify_live_repository(args)
    except (OSError, ValueError, build_repo.RepoError, subprocess.SubprocessError) as error:
        print(f"Public F-Droid repository verification failed: {error}", file=sys.stderr)
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
