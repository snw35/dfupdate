import dfupdate
import os
import sys
import types
import tempfile
import unittest
from unittest import mock

# ---- Inject a fake dockerfile_parse module BEFORE importing dfupdate ----
fake_mod = types.ModuleType("dockerfile_parse")


class FakeDockerfileParser:
    def __init__(self, *args, **kwargs):
        self._content = ""
        self.envs = {}
        self.baseimage = "python:3.10"

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        self._content = value
        # Simple parse: lines like "ENV KEY=VAL"
        envs = {}
        for line in value.splitlines():
            line = line.strip()
            if line.startswith("ENV "):
                rest = line[4:]
                # handle multiple pairs: KEY=VAL KEY2=VAL2
                parts = rest.split()
                for part in parts:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        envs[k.strip()] = v.strip()
        # Keep any pre-existing envs but overlay parsed ones
        self.envs.update(envs)


fake_mod.DockerfileParser = FakeDockerfileParser
sys.modules.setdefault("dockerfile_parse", fake_mod)


class TestGetNested(unittest.TestCase):
    def test_get_nested_direct(self):
        data = {"BASE": {"version": "3.11"}}
        self.assertEqual(dfupdate.get_nested(data, ["BASE", "version"]), "3.11")

    def test_get_nested_deep_anywhere(self):
        data = {"data": {"stuff": [{"BASE": {"version": "3.12"}}]}}
        self.assertEqual(dfupdate.get_nested(data, ["BASE", "version"]), "3.12")

    def test_get_nested_missing(self):
        self.assertIsNone(dfupdate.get_nested({}, ["BASE", "version"]))


class TestTopLevelUtilities(unittest.TestCase):
    def test_configure_logger(self):
        with mock.patch("logging.basicConfig") as m:
            dfupdate.logger.handlers.clear()
            dfupdate.configure_logger()
            m.assert_called_once()

    def test_load_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            dfupdate.load_file("nope.json")

    def test_atomic_write_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "file.txt")
            dfupdate.atomic_write_file(p, "hello")
            with open(p, "r", encoding="utf8") as fh:
                self.assertEqual(fh.read(), "hello")

    def test_get_remote_sha_success(self):
        # Fake streaming response
        class FakeResp:
            def __init__(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                pass

            def raise_for_status(self):
                pass

            def iter_content(self, chunk_size=1024):
                yield b"abc"
                yield b"123"

        with mock.patch("requests.get", return_value=FakeResp()):
            out = dfupdate.get_remote_sha("http://example.com/file.tgz")
            # Known sha256 of b"abc123"
            self.assertEqual(
                out, "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
            )

    def test_get_remote_sha_http_error(self):
        class FakeResp:
            def __init__(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                pass

            def raise_for_status(self):
                from requests import exceptions as e

                raise e.HTTPError(response=mock.Mock(status_code=404))

        with mock.patch("requests.get", return_value=FakeResp()):
            self.assertIsNone(dfupdate.get_remote_sha("http://fail"))


class TestDFUpdater(unittest.TestCase):
    def setUp(self):
        # Fresh updater with fake parser inside dfupdate
        self.updater = dfupdate.DFUpdater("new_ver.json", "Dockerfile")
        # Replace dfp with a fresh fake parser instance we can control
        self.updater.dfp = FakeDockerfileParser()

    @mock.patch(
        "dfupdate.load_file",
        return_value="FROM python:3.10\nENV FOO_VERSION=1.0\nENV BAR_VERSION=2.0 BAR_UPGRADE=false\n",
    )
    def test_get_dockerfile_versions_respects_upgrade_flag(self, _m):
        self.updater.get_dockerfile_versions()
        # BAR has upgrade=false and should be skipped
        self.assertEqual(self.updater.dockerfile_versions, {"FOO": "1.0"})

    @mock.patch(
        "dfupdate.load_file",
        return_value='{"BASE":{"version":"3.11"},"FOO":{"version":"1.1"}}',
    )
    def test_get_nvcheck_json(self, _m):
        self.updater.get_nvcheck_json()
        self.assertEqual(self.updater.nvcheck_json["BASE"]["version"], "3.11")

    def test_update_base_when_same(self):
        self.updater.dfp.baseimage = "python:3.11"
        self.updater.nvcheck_json = {"BASE": {"version": "3.11"}}
        with mock.patch.object(dfupdate, "logger") as mlog:
            self.updater.update_base()
            mlog.info.assert_any_call("Base image is up to date: %s", "3.11")

    def test_update_base_when_different(self):
        self.updater.dfp.baseimage = "python:3.10"
        self.updater.nvcheck_json = {"BASE": {"version": "3.11"}}
        with mock.patch.object(dfupdate, "logger") as mlog:
            self.updater.update_base()
            self.assertEqual(self.updater.dfp.baseimage, "python:3.11")
            mlog.info.assert_any_call("Base image updated.")

    @mock.patch("dfupdate.atomic_write_file")
    @mock.patch("dfupdate.get_remote_sha", return_value="deadbeef")
    def test_check_software_updates_and_writes(self, msha, matomic):
        # Prepare envs for URL/FILENAME/SHA logic
        self.updater.dfp.envs = {
            "FOO_VERSION": "1.0",
            "FOO_URL": "https://example.com/downloads",
            "FOO_FILENAME": "foo-1.0-linux.tgz",
            "FOO_SHA256": "old",
        }
        self.updater.dfp.content = "Dockerfile content here"
        # Detected software in Dockerfile
        self.updater.dockerfile_versions = {"FOO": "1.0"}
        # nvchecker says new version
        self.updater.nvcheck_json = {"FOO": {"version": "2.0"}}

        self.updater.check_software()

        # Should have updated envs
        self.assertEqual(self.updater.dfp.envs["FOO_VERSION"], "2.0")
        self.assertEqual(self.updater.dfp.envs["FOO_SHA256"], "deadbeef")
        # Should have written file once
        matomic.assert_called_once_with("Dockerfile", "Dockerfile content here")
        # URL was constructed with version substituted
        full_url_used = msha.call_args.args[0]
        self.assertIn("foo-2.0-linux.tgz", full_url_used)

    @mock.patch.object(dfupdate, "atomic_write_file")
    @mock.patch.object(dfupdate, "get_remote_sha", return_value=None)
    def test_check_software_writes_even_if_sha_missing(self, msha, matomic):
        self.updater.dfp.envs = {
            "FOO_VERSION": "1.0",
            "FOO_URL": "https://example.com",
            "FOO_FILENAME": "foo-1.0.tgz",
            "FOO_SHA256": "old",
        }
        self.updater.dfp.content = "x"
        self.updater.dockerfile_versions = {"FOO": "1.0"}
        self.updater.nvcheck_json = {"FOO": {"version": "2.0"}}

        with mock.patch.object(dfupdate, "logger") as mlog:
            self.updater.check_software()
            # Current implementation sets updated True before SHA is known,
            # so it still writes the Dockerfile.
            matomic.assert_called_once()
            mlog.error.assert_any_call("Got empty shasum! Skipping %s", "FOO")


class TestParseArgs(unittest.TestCase):
    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_parse_args(self, m):
        mock_ns = mock.Mock()
        mock_ns.nvcheck_file = "v.json"
        mock_ns.dockerfile = "Dfile"
        mock_ns.log_level = "DEBUG"
        m.return_value = mock_ns
        out = dfupdate.parse_args()
        self.assertEqual(out.nvcheck_file, "v.json")
        self.assertEqual(out.dockerfile, "Dfile")
        self.assertEqual(out.log_level, "DEBUG")


if __name__ == "__main__":
    unittest.main(verbosity=2)
