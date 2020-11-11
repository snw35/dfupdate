#!/usr/bin/env python3

# DFUPDATE_VERSION 0.0.6

import argparse
import configparser
from pkg_resources import parse_version
from pkg_resources import safe_version
import os
import glob
from dockerfile_parse import DockerfileParser
import hashlib
import json
import requests
import re

def getNvcheckVersions(versionFileName):
    nvcheckDict = {}
    with open(versionFileName, 'r') as versionFile:
        for line in versionFile:
            software, version = line.split()
            nvcheckDict[software] = version
        return nvcheckDict

def get_remote_sha(url):
    try:
        with requests.get(url, timeout=10) as r:
            sha256 = hashlib.sha256()
            for chunk in r.iter_content(chunk_size=1024):
                sha256.update(chunk)
            return sha256.hexdigest()
    except requests.exceptions.Timeout:
        print("Timeout, unable to retrive URL: " + url)
    except requests.exceptions.TooManyRedirects:
        print("Too many redirects, unable to retrive URL: " + url)
    except requests.exceptions.RequestException as e:
        print("Requests error, unable to retrive URL: " + url)
        raise SystemExit(e)

# Set variables
updated = False
configFileName = os.getcwd() + "/dfupdate.conf"
versionFileName = os.getcwd() + "/new_ver.txt"
dockerFileName = os.getcwd() + "/Dockerfile"

try:
    with open(versionFileName, 'r'):
        nvcheckDict = getNvcheckVersions(versionFileName)
except FileNotFoundError:
    nvcheckDict = {}
    print(versionFileName + " not found, continuing with Dockerfile base image check only.")

try:
    with open(configFileName, 'r'):
        config = configparser.ConfigParser()
        config.read(configFileName)
        baseImageRegex = config['DEFAULT'].get('baseImageRegex', ('.*'))
except FileNotFoundError:
    print(configFileName + " not found, unable to continue, config file must be in current working directory.")
    raise SystemExit

try:
    with open(dockerFileName, 'r+') as dFile:

        # Parse Dockerfile
        dfp = DockerfileParser()
        dfp.content = dFile.read()
        dockerfileImage,dockerfileTag = dfp.baseimage.split(':')

        # Get all versions of base image from dockerhub
        baseImageMatches = []
        baseImageRegexC = re.compile(baseImageRegex.strip("'"))

        dhubTagsJson = json.loads((requests.get('https://registry.hub.docker.com/v1/repositories/' + str(dockerfileImage) + '/tags')).content)
        for tag in dhubTagsJson:
            if baseImageRegexC.search(tag["name"]):
                baseImageMatches.append(tag["name"])

        dhubTagVersions = [parse_version(safe_version(str(tag))) for tag in baseImageMatches]
        dhubMaxVersion = max(dhubTagVersions)

        # Check base version for update
        if dhubMaxVersion > parse_version(str(dockerfileTag)):
            print("Base image has a newer version upstream: " + str(dhubMaxVersion))
            dfp.baseimage = str(dockerfileImage + ':' + str(dhubMaxVersion))
            updated = True

        elif dhubMaxVersion == parse_version(str(dockerfileTag)):
            print("Base image is up to date: " + str(dhubMaxVersion))

        elif dhubMaxVersion < parse_version(str(dockerfileTag)):
            print("Base image is newer than latest release on dockerhub! Parse error? - " + str(dhubMaxVersion))


        # Get all software packages present in dockerfile
        softwareList = list()
        versionDict = {}
        for env in dfp.envs:
            envsplit = env.split('_')
            firstPart = env.rsplit('_', 1)[0]
            lastWord = env.split('_')[-1]

            if (lastWord == "VERSION") and (dfp.envs[env]):
                print("Found a version number for " + firstPart + " " + dfp.envs[env])
                softwareList.append(firstPart)
                versionDict[firstPart] = dfp.envs[env]

        # Get all attributes of each software package
        urlDict = {}
        filenameDict = {}
        shaDict = {}
        for software in softwareList[:]:
            try:
                if dfp.envs[software + "_URL"]:
                    print("Found a download url for " + software + " " + dfp.envs[software + "_URL"])
                    urlDict[software] = dfp.envs[software + "_URL"]

                if dfp.envs[software + "_FILENAME"]:
                    print("Found a filename for " + software + " " + dfp.envs[software + "_FILENAME"])
                    filenameDict[software] = dfp.envs[software + "_FILENAME"]

                if dfp.envs[software + "_SHA256"]:
                    print("Found a hash for " + software + " " + dfp.envs[software + "_SHA256"])
                    shaDict[software] = dfp.envs[software + "_SHA256"]

                if dfp.envs[software + "_UPGRADE"]:
                    print("Found an upgrade setting for " + software + " " + dfp.envs[software + "_UPGRADE"])
                    if dfp.envs[software + "_UPGRADE"] == "false":
                        print("Upgrade set to false, removing from software list.")
                        softwareList.remove(software)

            except KeyError as e:
                print("ENV variable "  + str(e) + " not found for " + str(software))

        if nvcheckDict and softwareList:
            # Check each software package for updates
            for software in softwareList:
                try:
                    if nvcheckDict[software] == versionDict[software]:
                        print(software + " was found in both new_ver.txt and Dockerfile and has same version")
                    else:
                        print(software + " was found in both new_ver.txt and Dockerfile and has different versions")
                        dfp.envs[software + "_VERSION"] = str(nvcheckDict[software])
                        if shaDict[software]:
                            fullUrl = urlDict[software] + "/" + filenameDict[software]
                            fullUrl = fullUrl.replace(versionDict[software], str(nvcheckDict[software]))
                            print(fullUrl)
                            dfp.envs[software + "_SHA256"] = get_remote_sha(fullUrl)

                        updated = True
                except KeyError as e:
                    print(software + " was not found in both new_ver.txt and Dockerfile")

        if updated:
            print(dockerFileName + " has been updated!")
        else:
            print("No update necessary for " + dockerFileName)

except FileNotFoundError:
    print(dockerFileName + " not found, must be in current working directory.")
    raise SystemExit
