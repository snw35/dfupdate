"""
Unit tests for dfupdater
"""

import unittest
from unittest import mock
import requests
import dfupdate


class TestDFUpdater(unittest.TestCase):
    """
    Tests for main DFUpdater class
    """

    def setUp(self):
        """
        Patch common attributes such as the logger
        and DockerfileParser instance
        """
        patcher = mock.patch("dfupdate.logger")
        self.addCleanup(patcher.stop)
        self.mock_logger = patcher.start()
        self.version_file = "new_ver.json"
        self.dockerfile = "Dockerfile"
        self.updater = dfupdate.DFUpdater(self.version_file, self.dockerfile)

        parser = mock.patch("dockerfile_parse.DockerfileParser")
        self.addCleanup(parser.stop)
        self.mock_parser = parser.start()
        self.mock_parser_instance = mock.MagicMock()
        self.mock_parser.return_value = self.mock_parser_instance
        self.updater.dfp = self.mock_parser_instance

    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch(
        "builtins.open", new_callable=mock.mock_open, read_data='{"BASE": "1.2.3"}'
    )
    def test_load_versions_success(self, _mock_open, _mock_isfile):
        """
        Ensure versions can be loaded
        """
        self.updater.load_versions()
        self.assertEqual(self.updater.nvcheck["BASE"], "1.2.3")

    @mock.patch("os.path.isfile", return_value=False)
    def test_load_versions_file_not_found(self, _mock_isfile):
        """
        Test when nvchecker file is missing
        """
        with self.assertRaises(FileNotFoundError):
            self.updater.load_versions()
        self.mock_logger.error.assert_any_call(
            "%s not found. Must be present.", self.version_file
        )

    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch(
        "builtins.open",
        new_callable=mock.mock_open,
        read_data="FROM python:3.10\nENV BASE_VERSION=3.10\n",
    )
    def test_parse_dockerfile_success(self, _mock_open, _mock_isfile):
        """
        Check successful parsing
        """
        self.updater.parse_dockerfile()
        self.assertTrue(hasattr(self.mock_parser_instance, "content"))

    def test_update_base_no_change(self):
        """
        Test a base image update with no change needed
        """
        self.updater.nvcheck = {"BASE": "3.10"}
        self.mock_parser_instance.baseimage = "python:3.10"
        self.mock_parser_instance.envs = {}
        self.updater.update_base()
        self.mock_logger.info.assert_any_call("Base image is up to date: %s", "3.10")

    def test_update_base_update(self):
        """
        Test a base update with a valid change
        """
        self.updater.nvcheck = {"BASE": "3.11"}
        self.mock_parser_instance.baseimage = "python:3.10"
        self.mock_parser_instance.envs = {}
        self.updater.update_base()
        self.mock_logger.info.assert_any_call(
            "Base image out of date: %s -> %s", "3.10", "3.11"
        )
        self.assertTrue(self.updater.updated)

    @mock.patch("dfupdate.get_remote_sha", return_value="abc123")
    def test_update_software_upgrades(self, _mock_get_sha):
        """
        Test a software update with a valid change
        """
        test_envs = {
            "FOO_VERSION": "1.0",
            "FOO_UPGRADE": "true",
            "FOO_URL": "http://example.com",
            "FOO_FILENAME": "foo-2.0.tar.gz",
            "FOO_SHA256": "oldsha",
        }
        self.mock_parser_instance.envs = test_envs
        self.mock_parser_instance.content = "some dockerfile content"
        self.updater.nvcheck = {"FOO": "2.0"}
        with mock.patch.object(self.updater, "_atomic_write_dockerfile") as mock_atomic:
            self.updater.updated = False
            self.updater.update_software()
            mock_atomic.assert_called_once()
            self.mock_logger.info.assert_any_call(
                "%s updating: %s -> %s", "FOO", "1.0", "2.0"
            )

    def test_update_calls_all(self):
        """
        Check that calling update calls all the major steps, using spies
        """
        with mock.patch.object(
            self.updater, "load_versions"
        ) as mload, mock.patch.object(
            self.updater, "parse_dockerfile"
        ) as mparse, mock.patch.object(
            self.updater, "update_base"
        ) as mbase, mock.patch.object(
            self.updater, "update_software"
        ) as msoft:
            self.updater.update()
            mload.assert_called_once()
            mparse.assert_called_once()
            mbase.assert_called_once()
            msoft.assert_called_once()


class TestTopLevelFunctions(unittest.TestCase):
    """
    Test functions outside of the main
    DFUpdater class
    """

    @mock.patch("logging.basicConfig")
    def test_configure_logger(self, mock_basic_config):
        """
        Set up mock logger
        """
        dfupdate.logger.handlers.clear()
        dfupdate.configure_logger(level=42, print_log=False)
        mock_basic_config.assert_called_once()
        # Check that a handler is added when print_log=True
        with mock.patch.object(dfupdate.logger, "addHandler") as mock_add_handler:
            dfupdate.configure_logger(level=42, print_log=True)
            mock_add_handler.assert_called()

    @mock.patch(
        "builtins.open", new_callable=mock.mock_open, read_data='{"FOO": "1.0"}'
    )
    def test_get_nvcheck_versions_valid(self, mock_open):
        """
        Test loading a valid version
        """
        result = dfupdate.get_nvcheck_versions("dummy.json")
        self.assertEqual(result, {"FOO": "1.0"})
        mock_open.assert_called_with("dummy.json", "r", encoding="utf8")

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="{bad json}")
    def test_get_nvcheck_versions_invalid_json(self, _mock_open):
        """
        Test invalid JSON
        """
        with self.assertRaises(Exception):
            dfupdate.get_nvcheck_versions("dummy.json")

    @mock.patch("requests.get")
    def test_get_remote_sha_success(self, mock_get):
        """
        Test successful shasum calculation
        """

        class FakeResponse:
            """
            Provide a fake response
            """

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

            def raise_for_status(self):
                """
                Pass
                """

            def iter_content(self, chunk_size=1024):
                """
                Fake output
                """
                _ = chunk_size
                yield b"abc"

        mock_get.return_value = FakeResponse()
        result = dfupdate.get_remote_sha("http://example.com")
        self.assertIsInstance(result, str)

    @mock.patch(
        "requests.get", side_effect=requests.exceptions.RequestException("fail")
    )
    def test_get_remote_sha_failure(self, _mock_get):
        """
        Test an exception when fetching remote file
        """
        result = dfupdate.get_remote_sha("http://fail")
        self.assertIsNone(result)

    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_parse_args(self, mock_parse_args):
        """
        Test argument parsing
        """
        mock_args = mock.Mock()
        mock_args.version_file = "file.json"
        mock_args.dockerfile = "Dockerfile"
        mock_args.log_level = "DEBUG"
        mock_args.print_log = True
        mock_parse_args.return_value = mock_args
        args = dfupdate.parse_args()
        self.assertEqual(args.version_file, "file.json")
        self.assertEqual(args.log_level, "DEBUG")
        self.assertTrue(args.print_log)


if __name__ == "__main__":
    unittest.main()
