from __future__ import annotations

import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests
from urllib3.exceptions import MaxRetryError, SSLError as Urllib3SSLError

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import build_repo


def wrap_index_error(cause: Exception) -> build_repo.RepoError:
    try:
        raise build_repo.RepoError("fdroidserver could not verify the previous repository index") from cause
    except build_repo.RepoError as error:
        return error


def http_error(url: str, status: int) -> requests.HTTPError:
    response = requests.Response()
    response.status_code = status
    response.url = url
    return requests.HTTPError(response=response)


def hostname_error(url: str, verify_code: int = 62) -> requests.exceptions.SSLError:
    certificate_error = ssl.SSLCertVerificationError(1, "hostname mismatch")
    certificate_error.verify_code = verify_code
    transport_error = Urllib3SSLError(certificate_error)
    retry_error = MaxRetryError(None, url, reason=transport_error)
    request = requests.Request("GET", url).prepare()
    return requests.exceptions.SSLError(retry_error, request=request)


class BuildRepoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = build_repo.load_repository_config(REPO_ROOT / "repository.json")

    def test_add_link_uses_fdroid_syntax_and_repository_fingerprint(self) -> None:
        url = build_repo.add_repository_url(self.config)
        self.assertEqual(
            url,
            "https://fdroid.link/#https://f-repo.dobbyvpn.com/fdroid/repo?fingerprint="
            + self.config["fingerprint"].upper(),
        )

    def test_selected_release_provenance_rejects_wrong_source_and_run(self) -> None:
        validators = build_repo.load_product_validators(REPO_ROOT.parent / "DobbyVPN")
        version = "1.5.2"
        version_code = 1_005_002
        source_sha = "a" * 40
        run_id = 123
        run_number = 45
        assets = build_repo.expected_release_assets(version)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for name in assets:
                path = directory / name
                if name == "version.txt":
                    path.write_text(f"versionCode={version_code}\nversionName={version}\n", encoding="utf-8")
                else:
                    path.write_bytes(name.encode("utf-8"))
            validators.release_provenance.create_manifest(
                directory,
                tag=f"v{version}",
                version=version,
                source_sha=source_sha,
                release_run_id=run_id,
                release_run_number=run_number,
                android_version_code=version_code,
                assets=assets,
            )
            with self.assertRaises(validators.release_provenance.ProvenanceError):
                validators.release_provenance.verify_manifest(
                    directory,
                    tag=f"v{version}",
                    version=version,
                    source_sha="b" * 40,
                    release_run_id=run_id,
                    release_run_number=run_number,
                    android_version_code=version_code,
                    assets=assets,
                )
            with self.assertRaises(validators.release_provenance.ProvenanceError):
                validators.release_provenance.verify_manifest(
                    directory,
                    tag=f"v{version}",
                    version=version,
                    source_sha=source_sha,
                    release_run_id=run_id + 1,
                    release_run_number=run_number,
                    android_version_code=version_code,
                    assets=assets,
                )

    def test_initialize_accepts_empty_or_current_waiting_deployment_history(self) -> None:
        pages = json.dumps({"status": None}).encode()
        with patch.object(build_repo, "run_capture", side_effect=[pages, b"[[]]"]) as command, patch.object(
            build_repo, "download_previous_index", return_value={"packages": {}}
        ) as index:
            build_repo.verify_initialization_target(
                "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
            )
            self.assertIn("--paginate", command.call_args_list[1].args[0])
            self.assertIn("--slurp", command.call_args_list[1].args[0])
            index.assert_called_once()

        deployment = {"id": 21}
        current_status = {
            "state": "waiting",
            "log_url": "https://github.com/DobbyVPN/DobbyVPN/actions/runs/999/job/300",
        }
        with patch.object(build_repo, "run_capture", side_effect=[
            pages,
            json.dumps([[deployment]]).encode(),
            json.dumps([[current_status]]).encode(),
        ]) as command, patch.object(build_repo, "download_previous_index") as index:
            index.return_value = {"packages": {}}
            build_repo.verify_initialization_target(
                "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"],
                {"GITHUB_RUN_ID": "999"},
            )
            self.assertEqual(command.call_count, 3)
            self.assertIn("--paginate", command.call_args_list[2].args[0])
            self.assertIn("--slurp", command.call_args_list[2].args[0])
            index.assert_called_once()

    def test_initialize_rejects_nonempty_index_even_when_history_is_empty(self) -> None:
        with patch.object(build_repo, "run_capture", side_effect=[
            json.dumps({"status": None}).encode(), b"[[]]",
        ]), patch.object(
            build_repo, "download_previous_index", return_value={"packages": {build_repo.APP_ID: {}}}
        ) as index:
            with self.assertRaisesRegex(build_repo.RepoError, "contains packages"):
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )
            index.assert_called_once()

    def test_initialize_allows_only_exact_entry_jar_bootstrap_absence(self) -> None:
        pages = json.dumps({"status": None}).encode()
        entry_url = f"{self.config['repo_url']}/entry.jar"
        previous_url = f"{self.config['repo_url']}?fingerprint=ignored#fragment"
        absence_errors = [
            wrap_index_error(http_error(entry_url, 404)),
            wrap_index_error(hostname_error(entry_url)),
        ]
        for error in absence_errors:
            with self.subTest(cause=type(error.__cause__).__name__), patch.object(
                build_repo, "run_capture", side_effect=[pages, b"[[]]"]
            ), patch.object(build_repo, "download_previous_index", side_effect=error) as index:
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", previous_url, self.config["fingerprint"], {}
                )
                index.assert_called_once_with(previous_url, self.config["fingerprint"])

    def test_initialize_does_not_bypass_other_index_failures(self) -> None:
        entry_url = f"{self.config['repo_url']}/entry.jar"
        index_url = f"{self.config['repo_url']}/index-v2.json"
        errors = [
            wrap_index_error(http_error(index_url, 404)),
            wrap_index_error(http_error(entry_url, 500)),
            wrap_index_error(hostname_error(index_url)),
            wrap_index_error(hostname_error(entry_url, verify_code=10)),
            wrap_index_error(ValueError("repository fingerprint mismatch")),
            wrap_index_error(json.JSONDecodeError("bad index JSON", "not JSON", 0)),
        ]
        for error in errors:
            with self.subTest(cause=type(error.__cause__).__name__), patch.object(
                build_repo, "run_capture", side_effect=[json.dumps({"status": None}).encode(), b"[[]]"]
            ), patch.object(build_repo, "download_previous_index", side_effect=error):
                with self.assertRaises(build_repo.RepoError) as raised:
                    build_repo.verify_initialization_target(
                        "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                    )
                self.assertIs(raised.exception, error)

    def test_initialize_allows_two_failed_attempts_with_explicitly_skipped_deploy_step(self) -> None:
        pages = json.dumps({"status": None}).encode()
        deployments = [[{"id": 41}], [{"id": 42}]]

        def status(run_id: str) -> bytes:
            return json.dumps([[
                {
                    "state": "failure",
                    "log_url": f"https://github.com/DobbyVPN/DobbyVPN/actions/runs/{run_id}/job/{int(run_id) + 1000}",
                }
            ]]).encode()

        def job(run_id: str) -> bytes:
            return json.dumps({
                "run_id": int(run_id),
                "status": "completed",
                "steps": [{"name": "Deploy repository", "conclusion": "skipped"}],
            }).encode()

        with patch.object(build_repo, "run_capture", side_effect=[
            pages,
            json.dumps(deployments).encode(),
            status("101"),
            job("101"),
            status("102"),
            job("102"),
        ]) as command, patch.object(build_repo, "download_previous_index") as index:
            index.return_value = {"packages": {}}
            build_repo.verify_initialization_target(
                "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
            )
            self.assertEqual(command.call_count, 6)
            self.assertIn("actions/jobs/1101", command.call_args_list[3].args[0][-1])
            self.assertIn("actions/jobs/1102", command.call_args_list[5].args[0][-1])
            index.assert_called_once()

    def test_initialize_paginates_past_new_deployments_before_accepting_history(self) -> None:
        pages = json.dumps({"status": None}).encode()
        deployments = [[{"id": 43}, {"id": 44}], [{"id": 1}]]
        successful_status = [{
            "state": "success",
            "log_url": "https://github.com/DobbyVPN/DobbyVPN/actions/runs/100/job/200",
        }]
        with patch.object(build_repo, "run_capture", side_effect=[
            pages,
            json.dumps(deployments).encode(),
            json.dumps([[{"state": "failure", "log_url": "https://github.com/DobbyVPN/DobbyVPN/actions/runs/101/job/201"}]]).encode(),
            json.dumps({
                "run_id": 101,
                "status": "completed",
                "steps": [{"name": "Deploy repository", "conclusion": "skipped"}],
            }).encode(),
            json.dumps([[{"state": "failure", "log_url": "https://github.com/DobbyVPN/DobbyVPN/actions/runs/102/job/202"}]]).encode(),
            json.dumps({
                "run_id": 102,
                "status": "completed",
                "steps": [{"name": "Deploy repository", "conclusion": "skipped"}],
            }).encode(),
            json.dumps([successful_status]).encode(),
        ]) as command, patch.object(build_repo, "download_previous_index", side_effect=wrap_index_error(
            http_error(f"{self.config['repo_url']}/entry.jar", 404)
        )) as index:
            with self.assertRaises(build_repo.RepoError) as raised:
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )
            self.assertIs(raised.exception, index.side_effect)
            self.assertIn("--paginate", command.call_args_list[1].args[0])
            self.assertIn("per_page=100", command.call_args_list[1].args[0][-1])
            index.assert_called_once()

    def test_initialize_requires_verified_empty_index_after_deploy_step_ran(self) -> None:
        pages = json.dumps({"status": None}).encode()
        deployments = json.dumps([[{"id": 51}]]).encode()
        statuses = json.dumps([[
            {
                "state": "failure",
                "log_url": "https://github.com/DobbyVPN/DobbyVPN/actions/runs/150/job/250",
            }
        ]]).encode()
        job = json.dumps({
            "run_id": 150,
            "status": "completed",
            "conclusion": "failure",
            "steps": [{"name": "Deploy repository", "conclusion": "success"}],
        }).encode()
        absent_entry = wrap_index_error(http_error(f"{self.config['repo_url']}/entry.jar", 404))
        with patch.object(build_repo, "run_capture", side_effect=[pages, deployments, statuses, job]), \
             patch.object(build_repo, "download_previous_index", side_effect=absent_entry) as index:
            with self.assertRaises(build_repo.RepoError) as raised:
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )
            self.assertIs(raised.exception, absent_entry)
            index.assert_called_once()

        with patch.object(build_repo, "run_capture", side_effect=[pages, deployments, statuses, job]), \
             patch.object(
                 build_repo, "download_previous_index", return_value={"packages": {build_repo.APP_ID: {}}}
             ) as index:
            with self.assertRaisesRegex(build_repo.RepoError, "contains packages"):
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )
            index.assert_called_once_with(self.config["repo_url"], self.config["fingerprint"])

        with patch.object(build_repo, "run_capture", side_effect=[pages, deployments, statuses, job]), \
             patch.object(build_repo, "download_previous_index", return_value={"packages": {}}) as index:
            build_repo.verify_initialization_target(
                "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
            )
            index.assert_called_once()

    def test_initialize_requires_a_signed_empty_index_when_pages_are_already_built(self) -> None:
        with patch.object(build_repo, "run_capture", side_effect=[
            json.dumps({"status": "built"}).encode(), b"[[]]",
        ]), patch.object(build_repo, "download_previous_index", return_value={"packages": {}}) as index:
            build_repo.verify_initialization_target(
                "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
            )
            index.assert_called_once()

        with patch.object(build_repo, "run_capture", return_value=json.dumps({"status": "building"}).encode()):
            with self.assertRaisesRegex(build_repo.RepoError, "status"):
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )

        with patch.object(build_repo, "run_capture") as command:
            with self.assertRaisesRegex(build_repo.RepoError, "hosted on DobbyVPN/DobbyVPN"):
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/fdroid-repo", self.config["repo_url"], self.config["fingerprint"], {}
                )
            command.assert_not_called()

    def test_initialize_reports_malformed_native_history_if_index_verification_fails(self) -> None:
        index_error = build_repo.RepoError("index TLS/signature failure")
        with patch.object(build_repo, "run_capture", side_effect=[
            json.dumps({"status": None}).encode(), b"not JSON",
        ]), patch.object(
            build_repo, "download_previous_index", side_effect=index_error
        ) as index:
            with self.assertRaisesRegex(
                build_repo.RepoError,
                "deployment history API did not return valid JSON; index TLS/signature failure",
            ) as raised:
                build_repo.verify_initialization_target(
                    "gh", "DobbyVPN/DobbyVPN", self.config["repo_url"], self.config["fingerprint"], {}
                )
            self.assertIs(raised.exception.__cause__, index_error)
            index.assert_called_once()

    def test_release_asset_allowlist_rejects_unexpected_files(self) -> None:
        expected = build_repo.expected_release_assets("1.5.2")
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for name in expected:
                (directory / name).touch()
            (directory / "release-provenance.json").touch()
            build_repo.assert_release_files(directory, expected)
            (directory / "unexpected.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(build_repo.RepoError, "unexpected files"):
                build_repo.assert_release_files(directory, expected)

    def test_production_signer_mismatch_is_rejected(self) -> None:
        wrong_digest = b"0" * 64
        output = b"Signer #1 certificate SHA-256 digest: " + wrong_digest + b"\n"
        with tempfile.TemporaryDirectory() as raw, patch.object(build_repo, "run_capture", return_value=output):
            with self.assertRaisesRegex(build_repo.RepoError, "production signer"):
                build_repo.verify_apk_signer("apksigner", Path(raw) / "app.apk", {})

    def test_repository_key_fingerprint_is_immutable(self) -> None:
        with patch.object(build_repo, "certificate_fingerprint", return_value="0" * 64):
            with self.assertRaisesRegex(build_repo.RepoError, "differs from repository.json"):
                build_repo.verify_immutable_repository_key(
                    self.config, Path("repo.jks"), self.config["key_alias"], "keytool", {}
                )
        with patch.object(build_repo, "certificate_fingerprint", return_value=self.config["fingerprint"]):
            with self.assertRaisesRegex(build_repo.RepoError, "alias"):
                build_repo.verify_immutable_repository_key(
                    self.config, Path("repo.jks"), "replacement-key", "keytool", {}
                )

    def test_index_apk_sha256_and_size_must_match_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            apk = repo / f"{build_repo.APP_ID}_1005002.apk"
            apk.write_bytes(b"selected-signed-apk-bytes")
            record = {
                "name": apk.name,
                "sha256": build_repo.sha256_file(apk),
                "size": apk.stat().st_size,
            }
            record = {**record, "name": f"/{record['name']}"}
            index = {
                "packages": {
                    build_repo.APP_ID: {
                        "versions": {
                            record["sha256"]: {
                                "file": record,
                                "manifest": {"versionCode": 1_005_002, "versionName": "1.5.2"},
                            }
                        }
                    }
                }
            }
            checked = build_repo.verify_index_records(index, repo)
            self.assertEqual(checked, [{
                "name": record["name"].lstrip("/"),
                "sha256": record["sha256"],
                "size": record["size"],
                "version": "1.5.2",
                "version_code": 1_005_002,
            }])
            changed = json.loads(json.dumps(index))
            changed["packages"][build_repo.APP_ID]["versions"][record["sha256"]]["file"]["size"] += 1
            with self.assertRaisesRegex(build_repo.RepoError, "hash or size mismatch"):
                build_repo.verify_index_records(changed, repo)

    def test_previous_signed_index_records_must_have_compatible_provenance(self) -> None:
        validators = build_repo.load_product_validators(REPO_ROOT.parent / "DobbyVPN")
        valid = {
            "packages": {
                build_repo.APP_ID: {
                    "versions": {
                        "a" * 64: {
                            "file": {
                                "name": f"/{build_repo.APP_ID}_1005002.apk",
                                "sha256": "a" * 64,
                                "size": 123,
                            },
                            "manifest": {"versionCode": 1_005_002, "versionName": "1.5.2"},
                        }
                    }
                }
            }
        }
        self.assertEqual(
            build_repo.previous_index_records(valid, validators.version_metadata),
            [{
                "name": f"{build_repo.APP_ID}_1005002.apk",
                "sha256": "a" * 64,
                "size": 123,
                "version": "1.5.2",
                "version_code": 1_005_002,
            }],
        )
        malformed = json.loads(json.dumps(valid))
        malformed["packages"][build_repo.APP_ID]["versions"]["a" * 64]["manifest"]["versionCode"] = 1_005_003
        with self.assertRaisesRegex(build_repo.RepoError, "versionName and versionCode"):
            build_repo.previous_index_records(malformed, validators.version_metadata)

    def test_public_tree_allows_only_site_and_fdroid_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "assets").mkdir()
            (root / "fdroid" / "repo").mkdir(parents=True)
            (root / "repository.json").write_bytes((REPO_ROOT / "repository.json").read_bytes())
            (root / "index.html").write_text("public site", encoding="utf-8")
            for name in build_repo.SITE_ASSETS:
                relative = Path(name)
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_text("public asset", encoding="utf-8")
            for name in ("entry.jar", "entry.json", "index.jar", "index-v1.jar", "index-v1.json", "index-v2.json"):
                (root / "fdroid" / "repo" / name).write_text("generated index", encoding="utf-8")
            (root / "fdroid" / "repo" / "index.html").write_text("fdroid generated page", encoding="utf-8")
            (root / "fdroid" / "repo" / "index.css").write_text("fdroid generated css", encoding="utf-8")
            (root / "fdroid" / "repo" / "index.png").write_bytes(b"qr")
            (root / "fdroid" / "repo" / "icons").mkdir()
            (root / "fdroid" / "repo" / "icons" / "dobbyvpn.png").write_bytes(b"icon")
            (root / "fdroid" / "repo" / f"{build_repo.APP_ID}_1005002.apk").write_bytes(b"apk")
            build_repo.validate_public_tree(root, self.config["fingerprint"])
            (root / "fdroid" / "repo" / "config.yml").write_text("keystorepass: secret", encoding="utf-8")
            with self.assertRaisesRegex(build_repo.RepoError, "unexpected file"):
                build_repo.validate_public_tree(root, self.config["fingerprint"])

    def test_v1_and_v2_index_versions_and_hashes_must_agree(self) -> None:
        record = ("1.5.2", f"{build_repo.APP_ID}_1005002.apk", 50, "a" * 64)
        index_v1 = {
            "packages": {
                build_repo.APP_ID: [{
                    "versionName": record[0],
                    "apkName": record[1],
                    "versionCode": 1_005_002,
                    "size": record[2],
                    "hash": record[3],
                }]
            }
        }
        index_v2 = {
            "packages": {
                build_repo.APP_ID: {
                    "versions": {
                        record[3]: {
                            "manifest": {"versionName": record[0], "versionCode": 1_005_002},
                            "file": {"name": f"/{record[1]}", "size": record[2], "sha256": record[3]},
                        }
                    }
                }
            }
        }
        build_repo.verify_index_version_consistency(index_v1, index_v2)
        index_v2["packages"][build_repo.APP_ID]["versions"][record[3]]["file"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(build_repo.RepoError, "differ"):
            build_repo.verify_index_version_consistency(index_v1, index_v2)

    def test_binary_metadata_updates_version_without_builds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "com.dobby.vpn.yml"
            build_repo.format_metadata(REPO_ROOT / "metadata" / "com.dobby.vpn.yml", target, "2.3.4", 2_003_004)
            metadata = target.read_text(encoding="utf-8")
            self.assertIn("License: BUSL-1.1", metadata)
            self.assertIn("CurrentVersion: 2.3.4", metadata)
            self.assertIn("CurrentVersionCode: 2003004", metadata)
            self.assertIn("AllowedAPKSigningKeys: " + build_repo.ANDROID_SIGNER_SHA256, metadata)
            self.assertNotRegex(metadata, r"(?m)^Builds:")


if __name__ == "__main__":
    unittest.main()
