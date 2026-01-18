# Agent Instructions

## Repository overview
- Purpose: update Dockerfiles in place using nvchecker output, keeping base images and installed software versions aligned with `new_ver.json`.
- Primary workflow: run nvchecker to generate `new_ver.json`, then run `dfupdate.py` to update `FROM` lines and `ENV` variables (plus SHA256s for remote downloads).

## Key files
- `dfupdate.py`: main update script and CLI entrypoint.
- `README.md`: describes required `ENV` variables for software updates and base image config.
- `new_ver.json`: nvchecker output consumed by `dfupdate.py` (required) and used to update this repo's own `Dockerfile`.
- `nvchecker.toml`: nvchecker config used to generate `new_ver.json` for this repo's `Dockerfile`.
- `test_dfupdate.py`: tests (if you change behavior, update/extend tests accordingly).

## How dfupdate works (detailed)
- Parses the Dockerfile using `dockerfile_parse` and builds a model of:
  - `FROM` stages (index, alias, tokens, start/end lines).
  - `ENV` instructions and individual entries (supports `ENV KEY value` and `ENV KEY=value` styles).
- Collects installed software by scanning `ENV *_VERSION` values. It skips any software with `*_UPGRADE=false`.
- Resolves nvchecker versions by looking up keys in `new_ver.json`:
  - Tries nested lookup `data[SW]["version"]` and falls back to `data[SW]`.
  - For base images, it tries multiple keys per stage (see below).
- Computes edits in memory and applies them in place:
  - Uses token-level updates rather than regex, then writes with `atomic_write_file`.
  - Rewrites only changed `FROM` and `ENV` lines (line-based edits using start/end line numbers from `dockerfile_parse`).

## Base image update rules
- Every `FROM` line is treated as a stage; updates can target each stage independently.
- For a given stage, the desired version is looked up in `new_ver.json` using:
  - `BASE` for the final stage.
  - `BASE_<ALIAS>` or `<ALIAS>_BASE` when the stage is named.
  - `BASE_STAGE_<index>` or `BASE<index>` for stage index addressing.
  - `<REPO>_BASE` where `<REPO>` is derived from the base image repo name.
- The script updates the image tag or digest in the `FROM` token while preserving other `FROM` options.

## Software update rules (ENV-driven)
- Expected Dockerfile structure follows the README examples:
  - Version-only installs: `ENV SOFTWARE_VERSION x.y.z` and install via package manager.
  - Remote-file installs: `ENV SOFTWARE_VERSION`, `ENV SOFTWARE_URL`, `ENV SOFTWARE_FILENAME`, `ENV SOFTWARE_SHA256`.
- When a version changes:
  - `*_VERSION` is updated in all matching `ENV` entries.
  - If URL, filename, and SHA256 env vars are present, it downloads the new file and recomputes SHA256.
  - URL/filename templates can include `${SOFTWARE_VERSION}` or the current version string; these are substituted before download.
- Network behavior: `get_remote_sha` streams the file with `requests` and retries on network errors (tenacity exponential backoff). This is the most time-consuming path; mock it in tests.

## CLI usage
- `python dfupdate.py -n new_ver.json -d Dockerfile` (defaults are `new_ver.json` and `Dockerfile`).
- Logging is stdout-only; no log files are created.

## Notes for agents
- The repository’s primary purpose is in-place Dockerfile updates driven by nvchecker output and ENV-variable conventions from `README.md`.
- Be careful to preserve existing non-ENV Dockerfile content and comments; updates should be limited to `FROM` and `ENV` lines.
- Any changes to env parsing or base image matching should be reflected in both `README.md` and `test_dfupdate.py`.
