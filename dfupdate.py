#!/usr/bin/env python3
"""
DFUPDATE_VERSION 0.3.0

Updates a given Dockerfile based on the configuration
and output of nvchecker.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
from typing import Dict, Optional

import requests
from dockerfile_parse import DockerfileParser

logger = logging.getLogger("dfupdate")


class DFUpdater:
    """
    Dockerfile updater class.
    Contains functions to check and update
    a given Dockerfile.
    """

    def __init__(self, version_file: str, dockerfile: str):
        """
        Set up class attributes
        """
        self.version_file = version_file
        self.dockerfile = dockerfile
        self.nvcheck = {}
        self.updated = False
        self.dfp = DockerfileParser()

    def load_versions(self):
        """
        Load all software versions from nvchecker JSON file
        """
        if not os.path.isfile(self.version_file):
            logger.error("%s not found. Must be present.", self.version_file)
            raise FileNotFoundError(self.version_file)
        self.nvcheck = get_nvcheck_versions(self.version_file)

    def parse_dockerfile(self):
        """
        Parse and return Dockerfile contents
        """
        if not os.path.isfile(self.dockerfile):
            logger.error("%s not found. Must be present.", self.dockerfile)
            raise FileNotFoundError(self.dockerfile)
        with open(self.dockerfile, "r", encoding="utf8") as dfile:
            content = dfile.read()
        self.dfp.content = content

    def update_base(self):
        """
        Update base image if needed
        """
        base_image, base_tag = self.dfp.baseimage.rsplit(":", 1)
        if self.nvcheck.get("BASE") and self.nvcheck["BASE"] != str(base_tag):
            logger.info(
                "Base image out of date: %s -> %s", base_tag, self.nvcheck["BASE"]
            )
            self.dfp.baseimage = f"{base_image}:{self.nvcheck['BASE']}"
            self.updated = True
        else:
            logger.info("Base image is up to date: %s", base_tag)

    def update_software(self):
        """
        Identify all _VERSION variables and build lists of
        software to update
        """
        software_packages = {
            env.rsplit("_", 1)[0]: self.dfp.envs[env]
            for env in self.dfp.envs
            if env.endswith("_VERSION") and self.dfp.envs[env]
        }
        # Respect upgrade flag; build filtered list
        filtered_software = []
        for sw in software_packages:
            upgrade_flag = self.dfp.envs.get(f"{sw}_UPGRADE", "true").lower()
            if upgrade_flag == "false":
                logger.info("%s upgrade set to false, skipping.", sw)
                continue
            filtered_software.append(sw)

        # Package attributes for each software
        url_dict = {
            sw: self.dfp.envs.get(f"{sw}_URL")
            for sw in filtered_software
            if self.dfp.envs.get(f"{sw}_URL")
        }
        filename_dict = {
            sw: self.dfp.envs.get(f"{sw}_FILENAME")
            for sw in filtered_software
            if self.dfp.envs.get(f"{sw}_FILENAME")
        }
        sha_dict = {
            sw: self.dfp.envs.get(f"{sw}_SHA256")
            for sw in filtered_software
            if self.dfp.envs.get(f"{sw}_SHA256")
        }
        for sw in filtered_software:
            current_version = software_packages[sw]
            new_version = self.nvcheck.get(sw)
            if new_version is None:
                logger.warning("%s not found in %s, skipping.", sw, self.version_file)
                continue
            if new_version == current_version:
                logger.info("%s is up to date: %s", sw, current_version)
            else:
                logger.info(
                    "%s updating: %s -> %s",
                    sw,
                    current_version,
                    new_version,
                )
                self.dfp.envs[f"{sw}_VERSION"] = str(new_version)
                if sw in sha_dict and sw in url_dict and sw in filename_dict:
                    full_url = url_dict[sw] + "/" + filename_dict[sw]
                    full_url = full_url.replace(current_version, str(new_version))
                    logger.info("Retrieving new SHA256 for %s from %s", sw, full_url)
                    new_sha = get_remote_sha(full_url)
                    if new_sha:
                        self.dfp.envs[f"{sw}_SHA256"] = new_sha
                    else:
                        logger.error("Got empty shasum! Skipping %s", sw)
                self.updated = True
        if self.updated:
            self._atomic_write_dockerfile(self.dfp.content)
            logger.info("%s has been updated!", self.dockerfile)
        else:
            logger.info("No update necessary for %s", self.dockerfile)

    def _atomic_write_dockerfile(self, new_content: str):
        """
        Update the Dockerfile in an atomic operation
        (temp file create and move in-place) to prevent
        corruption and ensure consistent reads from CICD systems
        """
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(self.dockerfile), text=True
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf8") as temp_file:
                temp_file.write(new_content)
        except (OSError, ValueError, TypeError, UnicodeEncodeError) as e:
            logger.error("Failed writing to temporary Dockerfile: %s", e)
            raise
        try:
            shutil.move(temp_path, self.dockerfile)
        except (OSError, shutil.Error) as e:
            logger.error("Failed moving temporary Dockerfile to final location: %s", e)
            raise
        logger.debug("Dockerfile atomically updated.")
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except (
                OSError,
                FileNotFoundError,
                PermissionError,
            ):
                pass  # Avoid raising in cleanup

    def update(self):
        """
        Load software versions from nvchecker file
        Parse Dockerfile for current versions
        Update base image
        Update all software
        """
        self.load_versions()
        self.parse_dockerfile()
        self.update_base()
        self.update_software()


def configure_logger(level=logging.INFO, print_log=False):
    """
    Configure existing module level logger
    """
    if logger.hasHandlers():
        logger.handlers.clear()
    logging.basicConfig(
        filename="dfupdate.log",
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    if print_log:
        stdout_handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(stdout_handler)


def get_nvcheck_versions(version_file: str) -> Dict:
    """
    Load versions from nvchecker JSON file
    """
    with open(version_file, "r", encoding="utf8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            logger.error("JSON decode error for %s", f)
            raise e


def get_remote_sha(url: str, timeout: int = 10) -> Optional[str]:
    """
    Fetch the new software version and compute shasum
    to save into the Dockerfile
    """
    try:
        with requests.get(url, timeout=timeout) as r:
            r.raise_for_status()
            sha256 = hashlib.sha256()
            for chunk in r.iter_content(chunk_size=1024):
                sha256.update(chunk)
            return sha256.hexdigest()
    except requests.exceptions.Timeout:
        logger.error("Timeout, unable to retrieve URL: %s", url)
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
        description="Update Dockerfile based on nvchecker output"
    )
    parser.add_argument(
        "-n",
        "--nvchecker-file",
        dest="version_file",
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
    parser.add_argument(
        "-p",
        "--print-log",
        dest="print_log",
        action="store_true",
        help="Print log to stdout as well as logfile",
    )
    return parser.parse_args()


def main():
    """
    Set up argument parser, logger, and run dfupdater class
    """
    args = parse_args()
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    configure_logger(level=log_level, print_log=args.print_log)
    if args.print_log:
        logger.info("Printing log to stdout")
    updater = DFUpdater(args.version_file, args.dockerfile)
    updater.update()
    sys.exit(0)


if __name__ == "__main__":
    main()
