import unittest
from unittest import mock
import logging
import dfupdate

class dfupdate(unittest.TestCase):

    def setUp(self):
        self.logger = mock.Mock()
        self.version_file = 'test_ver.json'
        self.dockerfile = 'Dockerfile'
        self.updater = dfupdate(self.version_file, self.dockerfile, self.logger)

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data='{"BASE":"1.2.3"}')
    def test_load_versions_success(self, mock_open, mock_isfile):
        # Should load JSON from file
        self.updater.load_versions()
        self.assertEqual(self.updater.nvcheck["BASE"], "1.2.3")
        mock_open.assert_called_with(self.version_file, "r", encoding="utf8")

    @mock.patch('os.path.isfile', return_value=False)
    def test_load_versions_file_not_found(self, mock_isfile):
        with self.assertRaises(FileNotFoundError):
            self.updater.load_versions()
        self.logger.error.assert_any_call(f"{self.version_file} not found. Must be present.")

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data='')
    def test_update_dockerfile_not_found(self, mock_open, mock_isfile):
        # Version file exists, dockerfile does not
        mock_isfile.side_effect = [True, False]
        self.updater.nvcheck = {"BASE": "foo"}
        with self.assertRaises(FileNotFoundError):
            self.updater.update()
        self.logger.error.assert_any_call(f"{self.dockerfile} not found. Must be present.")

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data='FROM python:3.10\n')
    @mock.patch('dockerfile_parse.DockerfileParser')
    def test_update_base_image(self, mock_dfp, mock_open, mock_isfile):
        # Version file and Dockerfile exist, and base image is out of date
        mock_isfile.side_effect = [True, True]
        self.updater.nvcheck = {"BASE": "3.11"}
        # Mock DockerfileParser
        parser_instance = mock.Mock()
        parser_instance.baseimage = "python:3.10"
        parser_instance.envs = {}
        parser_instance.content = 'FROM python:3.10\n'
        mock_dfp.return_value = parser_instance
        with mock.patch.object(self.updater, '_atomic_write_dockerfile') as mock_atomic:
            self.updater.update()
            self.assertTrue(self.updater.updated)
            parser_instance.baseimage = f"python:3.11"
            mock_atomic.assert_called_once()
            self.logger.info.assert_any_call("Base image out of date: 3.10 -> 3.11")

    @mock.patch('os.path.isfile', side_effect=[True, True])
    @mock.patch('builtins.open', new_callable=mock.mock_open, read_data='FROM python:3.10\n')
    @mock.patch('dockerfile_parse.DockerfileParser')
    def test_update_no_change(self, mock_dfp, mock_open, mock_isfile):
        self.updater.nvcheck = {"BASE": "3.10"}
        parser_instance = mock.Mock()
        parser_instance.baseimage = "python:3.10"
        parser_instance.envs = {}
        parser_instance.content = 'FROM python:3.10\n'
        mock_dfp.return_value = parser_instance
        with mock.patch.object(self.updater, '_atomic_write_dockerfile') as mock_atomic:
            self.updater.update()
            self.assertFalse(self.updater.updated)
            mock_atomic.assert_not_called()
            self.logger.info.assert_any_call("Base image is up to date: 3.10")

    @mock.patch('shutil.move')
    @mock.patch('os.remove')
    @mock.patch('os.fdopen')
    @mock.patch('tempfile.mkstemp', return_value=(1, '/tmp/tempfile'))
    def test_atomic_write(self, mock_mkstemp, mock_fdopen, mock_remove, mock_move):
        # Simulate a file object
        temp_file = mock.Mock()
        mock_fdopen.return_value.__enter__.return_value = temp_file
        self.updater._atomic_write_dockerfile('content')
        temp_file.write.assert_called_with('content')
        mock_move.assert_called_with('/tmp/tempfile', self.dockerfile)

if __name__ == '__main__':
    unittest.main()
