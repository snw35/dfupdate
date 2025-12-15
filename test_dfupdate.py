import dfupdate
import json
import os
import tempfile
import unittest
from unittest import mock


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

    def test_load_file_content_not_found(self):
        with self.assertRaises(FileNotFoundError):
            dfupdate.load_file_content("nope.json")

    def test_atomic_write_file(self):
        import tempfile

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
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.dockerfile_path = os.path.join(self.tempdir.name, "Dockerfile")
        self.nvchecker_path = os.path.join(self.tempdir.name, "new_ver.json")
        with open(self.nvchecker_path, "w", encoding="utf8") as fh:
            json.dump({}, fh)
        self.updater = dfupdate.DFUpdater(self.nvchecker_path, self.dockerfile_path)

    def _write_dockerfile(self, content: str):
        with open(self.dockerfile_path, "w", encoding="utf8") as fh:
            fh.write(content)

    def test_get_dockerfile_versions_respects_upgrade_flag(self):
        self._write_dockerfile(
            "FROM python:3.10\nENV FOO_VERSION=1.0\nENV BAR_VERSION=2.0\nENV BAR_UPGRADE=false\n"
        )
        self.updater.get_dockerfile_versions()
        self.assertEqual(self.updater.dockerfile_versions, {"FOO": "1.0"})

    @mock.patch(
        "dfupdate.load_file_content",
        return_value='{"BASE":{"version":"3.11"},"FOO":{"version":"1.1"}}',
    )
    def test_get_nvcheck_json(self, _m):
        nvj = self.updater.get_nvcheck_json()
        self.assertEqual(nvj["BASE"]["version"], "3.11")

    def test_update_base_multi_stage(self):
        self._write_dockerfile(
            "FROM python:3.10 AS builder\n"
            "ENV FOO_VERSION=1.0\n"
            "FROM alpine:3.18\n"
            "ENV BAR_VERSION=2.0\n"
        )
        nvj = {"BASE_BUILDER": {"version": "3.11"}, "BASE": {"version": "3.19"}}
        self.updater.update_base(nvj)
        # Trigger write of base changes
        self.updater.check_software({})
        with open(self.dockerfile_path, "r", encoding="utf8") as fh:
            content = fh.read()
        self.assertIn("FROM python:3.11 AS builder", content)
        self.assertIn("FROM alpine:3.19", content)

    @mock.patch("dfupdate.get_remote_sha", return_value="deadbeef")
    def test_check_software_updates_across_stages(self, _msha):
        self._write_dockerfile(
            "FROM python:3.10 AS builder\n"
            "ENV FOO_VERSION=1.0\n"
            "ENV FOO_SHA256=old\n"
            "FROM python:3.10\n"
            "ENV FOO_VERSION=1.0\n"
            "ENV FOO_URL https://example.com\n"
            "ENV FOO_FILENAME foo-1.0.tgz\n"
            "ENV FOO_SHA256 old\n"
        )
        nvj = {"FOO": {"version": "2.0"}}
        self.updater.get_dockerfile_versions()
        self.updater.check_software(nvj)
        with open(self.dockerfile_path, "r", encoding="utf8") as fh:
            content = fh.read()
        self.assertEqual(content.count("FOO_VERSION=2.0"), 2)
        self.assertIn("FOO_SHA256=deadbeef", content)
        self.assertIn("FOO_SHA256 deadbeef", content)


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
