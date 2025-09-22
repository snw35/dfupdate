#!/usr/bin/env python3
"""
Updates a given Dockerfile based on the output of nvchecker.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile

import requests
from dockerfile_parse import DockerfileParser
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type,
    before_sleep_log,
)

logger = logging.getLogger("dfupdate")


class DFUpdater:
    """
    Dockerfile updater class.
    Contains functions to check and update
    a given Dockerfile.
    """

    def __init__(self, nvcheck_file: str, dockerfile: str):
        """
        Define class attributes
        """
        self.dfp = DockerfileParser()
        # Paths to dockerfile and nvchecker file
        self.nvcheck_file = nvcheck_file
        self.dockerfile = dockerfile
        # Map of software and version found in dockerfile
        self.dockerfile_versions = {}
        # Nvcheck JSON
        self.nvcheck_json = {}
        # Global update flag
        self.updated = False

    def get_dockerfile_versions(self):
        """
        Create list of software and versions found in dockerfile
        """
        self.dfp.content = load_file(self.dockerfile)

        software_packages = {
            key.rsplit("_", 1)[0]: value
            for key, value in self.dfp.envs.items()
            if key.endswith("_VERSION") and value
        }
        for sw, ver in software_packages.items():
            upgrade_flag = self.dfp.envs.get(f"{sw}_UPGRADE", "true").lower()
            if upgrade_flag == "false":
                logger.info("%s upgrade set to false, skipping.", sw)
                continue
            self.dockerfile_versions[sw] = ver

    def get_nvcheck_json(self):
        """
        Parse the nvcheck file content into JSON
        """
        try:
            self.nvcheck_json = json.loads(load_file(self.nvcheck_file))
        except json.JSONDecodeError as e:
            logger.error("JSON decode error for %s", self.nvcheck_file)
            raise e

    def update_base(self):
        """
        Update base image if needed.
        Handled separately from software as it always present and unique.
        """
        base_image, base_tag = self.dfp.baseimage.rsplit(":", 1)
        base_version = get_nested(self.nvcheck_json, ["BASE", "version"])
        if base_version != base_tag:
            logger.info("Base image out of date: %s -> %s", base_tag, base_version)
            self.dfp.baseimage = f"{base_image}:{base_version}"
            logger.info("Base image updated.")
        else:
            logger.info("Base image is up to date: %s", base_tag)

    def check_software(self):
        """
        Check identified software to see if an update is required, and call the update function if so.
        """
        for sw, ver in self.dockerfile_versions.items():
            # Attempt newer nvchecker format first
            new_ver = get_nested(self.nvcheck_json, [sw, "version"])
            # Fall back to old format
            if not new_ver:
                new_ver = self.nvcheck_json.get(sw)
                if not new_ver:
                    logger.warning("Failed to find %s in %s", sw, self.nvcheck_file)
                    continue
            if new_ver == ver:
                logger.info("%s is up to date", sw)
            else:
                self.updated = True
                self.update_software(sw, str(new_ver), ver)
        if self.updated:
            atomic_write_file(self.dockerfile, self.dfp.content)
            logger.info("%s has been updated!", self.dockerfile)

    def update_software(self, sw: str, new_ver: str, ver: str):
        """
        Update the specified software to the specified version.
        Version numbers are checked and validated by nvchecker external to this script, so assume they are valid until failure.
        """
        logger.info("Updating %s: %s -> %s", sw, ver, new_ver)
        df_url = self.dfp.envs.get(f"{sw}_URL")
        df_filename = self.dfp.envs.get(f"{sw}_FILENAME")
        df_sha = self.dfp.envs.get(f"{sw}_SHA256")
        if df_url and df_filename and df_sha:
            full_url = df_url + "/" + df_filename
            full_url = full_url.replace(ver, new_ver)
            logger.info("Retrieving new SHA256 for %s from %s", sw, full_url)
            new_sha = get_remote_sha(full_url)
            if new_sha:
                self.dfp.envs[f"{sw}_VERSION"] = new_ver
                self.dfp.envs[f"{sw}_SHA256"] = new_sha
            else:
                logger.error("Got empty shasum! Skipping %s", sw)
        else:
            logger.warning(
                "Attribute not found: URL:%s filename:%s sha:%s",
                df_url,
                df_filename,
                df_sha,
            )

    def update(self):
        """
        Class entrypoint. In order:
        Get all discovered software names from the dockerfile.
        Parse nvchecker file and load into JSON object.
        Update the base image if needed.
        Check each software package and updated if needed.
        """
        self.get_dockerfile_versions()
        self.get_nvcheck_json()
        self.update_base()
        self.check_software()


def configure_logger(level=logging.INFO):
    """
    Configure module level logger.
    Prints to standard out only, so no log files
    can interfere with git change detection in repos.
    """
    if logger.hasHandlers():
        logger.handlers.clear()
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def load_file(file_path: str):
    """
    Load file and return contents
    """
    if not os.path.isfile(file_path):
        logger.error("%s not found. Must be present.", file_path)
        raise FileNotFoundError(file_path)
    with open(file_path, "r", encoding="utf8") as content:
        return content.read()


def atomic_write_file(file_path: str, new_content: str):
    """
    Update a file with new content in an atomic operation
    (temp file create and move in-place) to prevent
    corruption and ensure consistent reads from CICD systems
    """
    temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path), text=True)
    try:
        with os.fdopen(temp_fd, "w", encoding="utf8") as temp_file:
            temp_file.write(new_content)
    except (OSError, ValueError, TypeError, UnicodeEncodeError) as e:
        logger.error("Failed writing to temporary file: %s", e)
        raise
    try:
        shutil.move(temp_path, file_path)
    except (OSError, shutil.Error) as e:
        logger.error("Failed moving temporary file to final location: %s", e)
        raise
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except (
                OSError,
                FileNotFoundError,
                PermissionError,
            ):
                pass  # Avoid raising in cleanup
    logger.debug("File atomically updated.")


@retry(
    retry=retry_if_exception_type(
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.RequestException,
        )
    ),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    stop=stop_after_attempt(3),
    before_sleep=before_sleep_log(logger, logging.INFO),
    reraise=True,
)
def get_remote_sha(url: str, timeout: int = 10) -> str | None:
    """
    Fetch a remote file and compute its sha256 checksum, with retry logic.
    Returns the sha256 as a hex string, or None if it fails.
    Retries on network errors with exponential backoff.
    """
    try:
        with requests.get(url, timeout=timeout, stream=True) as r:
            r.raise_for_status()
            sha256 = hashlib.sha256()
            for chunk in r.iter_content(chunk_size=1024):
                sha256.update(chunk)
            return sha256.hexdigest()
    except requests.exceptions.HTTPError as e:
        logger.error(
            "HTTP error %s for URL: %s",
            e.response.status_code if e.response else "Unknown",
            url,
        )
        return None
    except requests.exceptions.Timeout:
        logger.error("Timeout, unable to retrieve URL: %s", url)
    except requests.exceptions.ConnectionError:
        logger.error("Connection error, unable to retrieve URL: %s", url)
    except requests.exceptions.TooManyRedirects:
        logger.error("Too many redirects, unable to retrieve URL: %s", url)
    except requests.exceptions.RequestException as e:
        logger.error("Requests error retrieving URL: %s (%s)", url, e)
    return None


def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Updates a given Dockerfile based on an nvchecker output file."
    )
    parser.add_argument(
        "-n",
        "--nvchecker-file",
        dest="nvcheck_file",
        default="new_ver.json",
        help="Path to nvchecker JSON (default: new_ver.json)",
    )
    parser.add_argument(
        "-d",
        "--dockerfile",
        default="Dockerfile",
        help="Path to Dockerfile (default: Dockerfile)",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="INFO",
        help="Logging level (default: INFO)",
    )
    return parser.parse_args()


def get_nested(data: dict, path: list[str]) -> str | None:
    """
    Recursively search for a sequence of keys anywhere in a nested JSON-like structure.

    Args:
        data: dict representing the JSON.
        path: List of keys to follow, e.g. ["data", "BASE", "version"].

    Returns:
        A string containing the found value at the end of the path,
        or None if nothing is found.
    """
    if not isinstance(data, dict):
        return None

    if not path:
        return None

    key, *rest = path

    # If this is a dict and the key is present
    if key in data:
        if rest:
            return get_nested(data[key], rest)
        else:
            return data[key]

    # Recurse into values of the dict
    for val in data.values():
        if isinstance(val, dict):
            found = get_nested(val, path)
            if found:
                return found
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    found = get_nested(item, path)
                    if found:
                        return found

    return None


def main():
    """
    Set up argument parser, logger, and run dfupdater class
    """
    args = parse_args()
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    configure_logger(level=log_level)
    updater = DFUpdater(args.nvcheck_file, args.dockerfile)
    try:
        updater.update()
    except (OSError, FileNotFoundError, PermissionError, UnicodeEncodeError) as e:
        logger.exception("Update failed: %s", e)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
