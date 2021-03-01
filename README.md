# dfupdate

* [Travis CI: ![Build Status](https://travis-ci.org/snw35/dfupdate.svg?branch=master)](https://travis-ci.org/snw35/dfupdate)
* [Dockerhub: snw35/dfupdate](https://hub.docker.com/r/snw35/dfupdate)

Dockerfile Automatic Updater.

Python script to automatically update both the base image and included software in a Dockerfile.

This image, working with [snw35/nvchecker](https://github.com/snw35/nvchecker), automatically updates itself.

**NOTE:** compatible with nvchecker versions 2.x and above.

## Requirements

Requires a `dfupdate.conf` config file in the current working directory when run.

This file has the following contents:

```
[DEFAULT]

# A regex used to filter tags when updating the Dockerfile base image
# Defaults to '.*'
baseImageRegex = ''

# Full path to the file containing nvchecker new versions (newver config entry)
# Defaults to './new_ver.json'
versionFileName = ''

# Full path to the Dockerfile to update
# Defaults to './Dockerfile'
dockerFileName = ''
```

It will:
 * Use `baseImageRegex` to search for an updated base image tag and write it into the Dockerfile at `dockerFileName`.
 * Use the versions stored in `versionFileName` to update the software in the Dockerfile at `dockerFileName`.

### Required ENV Variables

Install software in your Dockerfile with the following ENV vars:

#### When retrieving a remote file
 * SOFTWARE_VERSION - the bare version number, e.g 1.2.3
 * SOFTWARE_URL - the base download URL without the filename. Can include $SOFTWARE_VERSION if necessary.
 * SOFTWARE_FILENAME - the filename (last part) of the download URL. Can include $SOFTWARE_VERSION if necessary.
 * SOFTWARE_SHA256 - the expected sha256 of the retrieved file.

This will result in a block similar to e.g, for kubectl:
```
ENV KUBECTL_VERSION 1.16.1
ENV KUBECTL_URL https://storage.googleapis.com/kubernetes-release/release/v$KUBECTL_VERSION/bin/linux/amd64
ENV KUBECTL_FILENAME kubectl
ENV KUBECTL_SHA256 69cfb3eeaa0b77cc4923428855acdfc9ca9786544eeaff9c21913be830869d29

RUN wget $KUBECTL_URL/$KUBECTL_FILENAME \
  && echo "$KUBECTL_SHA256  ./$KUBECTL_FILENAME" | sha256sum -c - \
  && chmod +x ./$KUBECTL_FILENAME
```

#### When installing via package manager
 * SOFTWARE_VERSION - the bare version number, e.g 1.2.3

This will result in, e.g for pip:
```
ENV REQUESTS_VERSION 2.22.0
ENV DOCKERFILE_PARSE_VERSION 0.0.15

RUN pip3 install --no-cache-dir \
    requests==${REQUESTS_VERSION} \
    dockerfile_parse==${DOCKERFILE_PARSE_VERSION} \
```

### dfupdate.conf Config File

Create a `dfupdate.conf` file in the same directory as your `Dockerfile` with the following content:
```
[DEFAULT]

baseImageRegex = '\d+\.\d+\.?\d?'
```
Set the `baseImageRegex` value to a regular expression that will match the base images you want. This is required to filter out e.g beta and release candidate versions, as Python's version parser will often select these otherwise. The example given is suitable for alpine.

### The new_ver.json file

This file is the output from [nvchecker](https://github.com/lilydjwg/nvchecker), run from [snw35/nvchecker](https://github.com/snw35/nvchecker).

Nvchecker is used to retrieve the latest versions of packaged software, and must be configured for your repo before going ahead.

## How To Use

While in the root directory of a compatible project, run the container with the current directory bind-mounted to `/data`:
`docker run -it --rm --mount type=bind,source=${PWD},target=/data/ -w /data snw35/dfupdate:latest`
