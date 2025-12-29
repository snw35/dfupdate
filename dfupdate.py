#!/usr/bin/env python3
"""
Updates a given Dockerfile based on the output of nvchecker.
"""

import argparse
import hashlib
import io
import json
import logging
import os
import shutil
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from typing import Sequence, cast

import requests
from dockerfile_parse import DockerfileParser
from dockerfile_parse.parser import image_from
from dockerfile_parse.util import WordSplitter
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type,
    before_sleep_log,
)

logger = logging.getLogger("dfupdate")


@dataclass
class Stage:
    index: int
    image: str | None
    alias: str | None
    tokens: list[str]
    startline: int
    endline: int
    image_token_index: int | None
    changed: bool = False


@dataclass
class EnvEntry:
    key: str
    value: str
    raw_value: str
    style: str
    token_index: int


@dataclass
class EnvInstruction:
    stage_index: int
    startline: int
    endline: int
    tokens: list[str]
    entries: list[EnvEntry]
    changed: bool = False


@dataclass
class FileEdit:
    startline: int
    endline: int
    new_lines: list[str]


class DFUpdater:
    """
    Dockerfile updater class.
    Contains functions to check and update
    a given Dockerfile.
    """

    def __init__(self, nvcheck_file: str, dockerfile: str):
        """
        Initilise class attributes and dockerfile parser.

        Args:
            nvcheck_file: absolute or relative path to nvchecker file.
            dockerfile: absolute or relative path to dockerfile.
        """
        self.dfp: DockerfileParser | None = None
        # Paths to dockerfile and nvchecker file
        self.nvcheck_file = nvcheck_file
        self.dockerfile = dockerfile
        # Map of software and version found in dockerfile
        self.dockerfile_versions = {}
        self.software_versions: dict[str, set[str]] = {}
        # Global update flag
        self.updated = False
        # Parsed dockerfile state
        self.lines: list[str] | None = None
        self.stages: list[Stage] = []
        self.env_instructions: list[EnvInstruction] = []
        self.env_entries_by_name: dict[str, list[tuple[EnvInstruction, EnvEntry]]] = {}

    def _ensure_loaded(self):
        """
        Load Dockerfile content into memory and parse structure for
        stages and ENV instructions.
        """
        if self.lines is not None:
            return
        self.lines = load_file_content(self.dockerfile).splitlines(keepends=True)
        content = "".join(self.lines)
        self.dfp = DockerfileParser(fileobj=io.StringIO(content), cache_content=True)
        self.stages = self._parse_stages()
        self.env_instructions = self._parse_env_instructions()
        self.env_entries_by_name = self._index_env_entries()

    def _parse_stages(self) -> list[Stage]:
        if not self.dfp:
            return []
        stages: list[Stage] = []
        stage_index = -1
        for instruction in self.dfp.structure:
            if instruction["instruction"] != "FROM":
                continue
            stage_index += 1
            tokens = cast(
                list[str], list(WordSplitter(instruction["value"]).split(dequote=False))
            )
            image, alias = image_from(instruction["value"])
            image_token_index = self._find_image_token_index(tokens)
            stages.append(
                Stage(
                    index=stage_index,
                    image=image,
                    alias=alias,
                    tokens=tokens,
                    startline=instruction["startline"],
                    endline=instruction["endline"],
                    image_token_index=image_token_index,
                )
            )
        return stages

    def _find_image_token_index(self, tokens: Sequence[str]) -> int | None:
        for idx, token in enumerate(tokens):
            if token.startswith("--"):
                continue
            return idx
        return None

    def _parse_env_entries(self, tokens: list[str]) -> list[EnvEntry]:
        entries: list[EnvEntry] = []
        if "=" not in tokens[0]:
            key = tokens[0]
            raw_value = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            value = WordSplitter(raw_value).dequote() if raw_value else ""
            entries.append(
                EnvEntry(
                    key=key,
                    value=value,
                    raw_value=raw_value,
                    style="space",
                    token_index=0,
                )
            )
            return entries

        for idx, token in enumerate(tokens):
            if "=" not in token:
                continue
            key, raw_value = token.split("=", 1)
            value = WordSplitter(raw_value).dequote()
            entries.append(
                EnvEntry(
                    key=key,
                    value=value,
                    raw_value=raw_value,
                    style="equals",
                    token_index=idx,
                )
            )
        return entries

    def _parse_env_instructions(self) -> list[EnvInstruction]:
        if not self.dfp:
            return []
        env_instructions: list[EnvInstruction] = []
        stage_index = -1
        for instruction in self.dfp.structure:
            if instruction["instruction"] == "FROM":
                stage_index += 1
                continue
            if instruction["instruction"] != "ENV":
                continue
            tokens = cast(
                list[str], list(WordSplitter(instruction["value"]).split(dequote=False))
            )
            if not tokens:
                continue
            entries = self._parse_env_entries(tokens)
            env_instructions.append(
                EnvInstruction(
                    stage_index=stage_index,
                    startline=instruction["startline"],
                    endline=instruction["endline"],
                    tokens=tokens,
                    entries=entries,
                )
            )
        return env_instructions

    def _index_env_entries(self) -> dict[str, list[tuple[EnvInstruction, EnvEntry]]]:
        mapping: defaultdict[str, list[tuple[EnvInstruction, EnvEntry]]] = defaultdict(
            list
        )
        for env_instruction in self.env_instructions:
            for entry in env_instruction.entries:
                mapping[entry.key].append((env_instruction, entry))
        return dict(mapping)

    def _format_env_value(self, raw_value: str, new_value: str) -> str:
        if (
            raw_value
            and len(raw_value) >= 2
            and raw_value[0] == raw_value[-1]
            and raw_value[0] in ("'", '"')
        ):
            return f"{raw_value[0]}{new_value}{raw_value[0]}"
        if any(ch.isspace() for ch in new_value):
            return f'"{new_value}"'
        return new_value

    def _update_env_entry(
        self, env_instruction: EnvInstruction, entry: EnvEntry, new_value: str
    ) -> bool:
        formatted_value = self._format_env_value(entry.raw_value, new_value)
        if entry.style == "equals":
            new_token = f"{entry.key}={formatted_value}"
            if env_instruction.tokens[entry.token_index] == new_token:
                return False
            env_instruction.tokens[entry.token_index] = new_token
        else:
            new_token = formatted_value
            if (
                len(env_instruction.tokens) < 2
                or env_instruction.tokens[1] != new_token
                or env_instruction.tokens[0] != entry.key
            ):
                env_instruction.tokens = [entry.key, new_token]
            else:
                return False
        entry.value = new_value
        entry.raw_value = formatted_value
        env_instruction.changed = True
        self.updated = True
        return True

    def _update_env_value(self, env_name: str, new_value: str) -> bool:
        changed = False
        for env_instruction, entry in self.env_entries_by_name.get(env_name, []):
            changed = (
                self._update_env_entry(env_instruction, entry, new_value) or changed
            )
        return changed

    def _substitute_version_tokens(
        self, text: str | None, sw: str, new_ver: str, current_example: str
    ) -> str:
        """
        Replace common version placeholders with the new version.
        Supports ${SW_VERSION}, $SW_VERSION, and the literal current version string.
        """
        if not text:
            return ""
        sw_upper = sw.upper()
        sw_lower = sw.lower()
        placeholders = [
            f"${{{sw_upper}_VERSION}}",
            f"${sw_upper}_VERSION",
            f"${{{sw_lower}_VERSION}}",
            f"${sw_lower}_VERSION",
        ]
        result = text
        for placeholder in placeholders:
            result = result.replace(placeholder, new_ver)
        if current_example:
            result = result.replace(current_example, new_ver)
        return result

    def _get_env_value(
        self, env_name: str, stage_index: int | None = None
    ) -> str | None:
        entries = self.env_entries_by_name.get(env_name, [])
        if stage_index is not None:
            for env_instruction, entry in entries:
                if env_instruction.stage_index == stage_index and entry.value:
                    return entry.value
        for _, entry in entries:
            if entry.value:
                return entry.value
        return None

    def _generate_edits(self) -> list[FileEdit]:
        edits: list[FileEdit] = []
        for stage in self.stages:
            if stage.changed and stage.image_token_index is not None:
                new_content = f"FROM {' '.join(stage.tokens)}\n"
                edits.append(FileEdit(stage.startline, stage.endline, [new_content]))
        for env_instruction in self.env_instructions:
            if env_instruction.changed:
                new_content = f"ENV {' '.join(env_instruction.tokens)}\n"
                edits.append(
                    FileEdit(
                        env_instruction.startline,
                        env_instruction.endline,
                        new_content.splitlines(keepends=True),
                    )
                )
        return sorted(edits, key=lambda edit: edit.startline)

    def _apply_edits(self, edits: list[FileEdit]):
        if self.lines is None:
            return
        updated_lines = self.lines[:]
        offset = 0
        for edit in edits:
            start = edit.startline + offset
            end = edit.endline + offset
            updated_lines[start : end + 1] = edit.new_lines
            offset += len(edit.new_lines) - (end - start + 1)
        self.lines = updated_lines

    def _write_changes(self):
        edits = self._generate_edits()
        if not edits or self.lines is None:
            return
        self._apply_edits(edits)
        new_content = "".join(self.lines)
        atomic_write_file(self.dockerfile, new_content)
        self.dfp = DockerfileParser(
            fileobj=io.StringIO(new_content), cache_content=True
        )
        logger.info("%s has been updated!", self.dockerfile)

    def _split_image(self, image: str | None) -> tuple[str | None, str, str | None]:
        if not image:
            return None, "", None
        if "@" in image:
            repo, digest = image.split("@", 1)
            return repo, "@", digest
        last_slash = image.rfind("/")
        last_colon = image.rfind(":")
        if last_colon > last_slash:
            return image[:last_colon], ":", image[last_colon + 1 :]
        return image, ":", None

    def _repo_key(self, repo: str | None) -> str | None:
        if not repo:
            return None
        name = repo.split("/")[-1]
        name = name.split(":")[0]
        key = name.replace("-", "_").upper()
        return key or None

    def _base_version_for_stage(self, stage: Stage, nvcheck_json: dict) -> str | None:
        repo, _, _ = self._split_image(stage.image)
        candidates = []
        if self.stages and stage.index == len(self.stages) - 1:
            candidates.append("BASE")
        if stage.alias:
            alias = stage.alias.upper()
            candidates.extend([f"BASE_{alias}", f"{alias}_BASE"])
        candidates.append(f"BASE_STAGE_{stage.index}")
        candidates.append(f"BASE{stage.index}")
        repo_key = self._repo_key(repo)
        if repo_key:
            candidates.append(f"{repo_key}_BASE")
        seen: set[str] = set()
        for key in candidates:
            if key in seen:
                continue
            seen.add(key)
            version = get_nested(nvcheck_json, [key, "version"])
            if not version:
                version = nvcheck_json.get(key)
            if version:
                return str(version)
        return None

    def _stage_label(self, stage: Stage) -> str:
        return stage.alias or f"stage {stage.index}"

    def get_dockerfile_versions(self):
        """
        Create list of software and versions found in dockerfile.
        """
        self._ensure_loaded()
        self.dockerfile_versions = {}
        self.software_versions = {}
        upgrade_flags: dict[str, str] = {}
        for env_name, entries in self.env_entries_by_name.items():
            if not env_name.endswith("_UPGRADE"):
                continue
            sw = env_name.rsplit("_", 1)[0]
            value = entries[-1][1].value.lower() if entries else ""
            upgrade_flags[sw] = value

        for env_name, entries in self.env_entries_by_name.items():
            if not env_name.endswith("_VERSION"):
                continue
            sw = env_name.rsplit("_", 1)[0]
            if upgrade_flags.get(sw) == "false":
                logger.info("%s upgrade set to false, skipping.", sw)
                continue
            values = {entry.value for _, entry in entries if entry.value}
            if not values:
                continue
            self.software_versions[sw] = values
            self.dockerfile_versions[sw] = next(iter(values))

    def get_nvcheck_json(self) -> dict:
        nvcheck_content = load_file_content(self.nvcheck_file)
        try:
            return json.loads(nvcheck_content)
        except json.JSONDecodeError as e:
            logger.error("JSON decode error for %s", self.nvcheck_file)
            raise e

    def update_base(self, nvcheck_json: dict):
        """
        Update base image if needed.
        Handled separately from software as it always present and unique.

        Args:
            nvcheck_json: dictionary containing parsed nvchecker file JSON.
        """
        self._ensure_loaded()
        for stage in self.stages:
            repo, separator, current_tag = self._split_image(stage.image)
            desired_version = self._base_version_for_stage(stage, nvcheck_json)
            if not desired_version:
                continue
            if stage.image_token_index is None or not repo:
                logger.warning(
                    "Unable to update base image for %s", self._stage_label(stage)
                )
                continue
            if current_tag == desired_version:
                logger.info(
                    "Base image is up to date for %s: %s",
                    self._stage_label(stage),
                    current_tag or "",
                )
                continue
            logger.info(
                "Base image out of date for %s: %s -> %s",
                self._stage_label(stage),
                current_tag,
                desired_version,
            )
            separator_to_use = separator or ":"
            stage.tokens[stage.image_token_index] = (
                f"{repo}{separator_to_use}{desired_version}"
            )
            stage.changed = True
            self.updated = True
            logger.info("Base image updated for %s.", self._stage_label(stage))

    def check_software(self, nvcheck_json: dict):
        """
        Check identified software to see if an update is required, and call the update function if so.

        Args:
            nvcheck_json: dictionary containing parsed nvchecker file JSON.
        """
        self._ensure_loaded()
        for sw, ver in self.dockerfile_versions.items():
            new_ver = get_nested(nvcheck_json, [sw, "version"])
            if not new_ver:
                new_ver = nvcheck_json.get(sw)
                if not new_ver:
                    logger.warning("Failed to find %s in %s", sw, self.nvcheck_file)
                    continue
            new_ver_str = str(new_ver)
            current_values = self.software_versions.get(sw, {ver})
            if current_values == {new_ver_str}:
                logger.info("%s is up to date", sw)
            else:
                self.update_software(sw, new_ver_str, current_values)
        if self.updated:
            self._write_changes()

    def update_software(self, sw: str, new_ver: str, current_versions: set[str]):
        """
        Update the specified software.

        Args:
            sw: the software name to update (as found in the dockerfile).
            new_ver: the new version to update to.
            current_versions: set of currently detected versions.
        """
        current_example = next(iter(current_versions), "")
        logger.info("Updating %s: %s -> %s", sw, current_example, new_ver)

        # Update bare ENV versions
        version_env = f"{sw}_VERSION"
        self._update_env_value(version_env, new_ver)

        # Use the first stage where the version appears to look up related envs
        stage_hint = None
        if self.env_entries_by_name.get(version_env):
            stage_hint = self.env_entries_by_name[version_env][0][0].stage_index

        # Check for remote URL and get new shasum
        df_url = self._get_env_value(f"{sw}_URL", stage_hint)
        df_filename = self._get_env_value(f"{sw}_FILENAME", stage_hint)
        df_sha = self._get_env_value(f"{sw}_SHA256", stage_hint)
        if df_url and df_filename and df_sha:
            logger.info("Found remote URL, fetching and calculating new shasum")
            url_template = self._substitute_version_tokens(
                df_url, sw, new_ver, current_example
            )
            filename_template = self._substitute_version_tokens(
                df_filename, sw, new_ver, current_example
            )
            full_url = url_template.rstrip("/") + "/" + filename_template.lstrip("/")
            logger.info("Retrieving new SHA256 for %s from %s", sw, full_url)
            new_sha = get_remote_sha(full_url)
            if new_sha:
                self._update_env_value(f"{sw}_SHA256", new_sha)
            else:
                logger.error("Got empty shasum! Skipping %s", sw)
                # Reset ENV values to avoid updating
                if current_example:
                    self._update_env_value(version_env, current_example)
        else:
            logger.info(
                "Attribute not found: URL:%s filename:%s sha:%s",
                df_url,
                df_filename,
                df_sha,
            )

    def update(self):
        """
        Class entrypoint. Operations in order are:
        Parse nvcheck file JSON.
        Get all discovered software names from the dockerfile.
        Update the base image if needed.
        Check each software package and updated if needed.
        """
        nvcheck_json = self.get_nvcheck_json()
        self.lines = None
        self.stages = []
        self.env_instructions = []
        self.env_entries_by_name = {}
        self.dfp = None
        self.updated = False
        self._ensure_loaded()
        self.get_dockerfile_versions()
        self.update_base(nvcheck_json)
        self.check_software(nvcheck_json)


def configure_logger(level=logging.INFO):
    """
    Configure module level logger.
    Prints to standard out only, so no log files
    can interfere with git change detection in repos.

    Args:
        level: logging level to use.
    """
    if logger.hasHandlers():
        logger.handlers.clear()
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def load_file_content(file_path: str):
    """
    Load file and return contents as a string

    Args:
        file_path: path to file.
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

    Args:
        file_path: path to file.
        new_content: new contents to write as a string.
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

    Args:
        url: the URL to fetch the file from.
        timeout: the timeout to use in seconds, default 10.

    Returns:
        The sha256sum of the file as a string.
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
            "HTTP error %d %s for URL: %s",
            e.response.status_code,
            str(e.response.reason),
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
