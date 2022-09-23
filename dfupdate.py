#!/usr/bin/env python3

# DFUPDATE_VERSION 0.2.0

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
        return json.load(versionFile)

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
versionFileName = (os.getcwd() + '/new_ver.json')
dockerFileName = (os.getcwd() + '/Dockerfile')

try:
    with open(versionFileName, 'r'):
        nvcheckDict = getNvcheckVersions(versionFileName)
except FileNotFoundError:
    nvcheckDict = {}
    print(versionFileName + " not found, must be in the current working directory.")
    raise SystemExit

try:
    with open(dockerFileName, 'r+') as dFile:

        # Parse Dockerfile
        dfp = DockerfileParser()
        dfp.content = dFile.read()
        dockerfileImage,dockerfileTag = dfp.baseimage.split(':')

        # Check base version for update
        try:
            if nvcheckDict["BASE"] != str(dockerfileTag):
                print("Base image has a newer version upstream: " + str(nvcheckDict["BASE"]))
                dfp.baseimage = str(dockerfileImage + ':' + str(nvcheckDict["BASE"]))
                updated = True
            else:
                print("Base image is up to date: " + nvcheckDict["BASE"])
        except KeyError as e:
            print("No value for " + str(e) + " found in " + versionFileName + ", unable to update container base image.")

        # Get all software packages present in dockerfile
        softwareList = list()
        versionDict = {}
        for env in dfp.envs:
            sofwareName = env.rsplit('_', 1)[0]
            softwareAttribute = env.split('_')[-1]

            if (softwareAttribute == "VERSION") and (dfp.envs[env]):
                print("Found a version number for " + sofwareName + " " + dfp.envs[env])
                softwareList.append(sofwareName)
                versionDict[sofwareName] = dfp.envs[env]

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
                        print(software + " was found in both " + versionFileName + " and " + dockerFileName + " and has same version")
                    else:
                        print(software + " was found in both " + versionFileName + " and " + dockerFileName + " and has different versions")
                        dfp.envs[software + "_VERSION"] = str(nvcheckDict[software])
                        if shaDict[software]:
                            fullUrl = urlDict[software] + "/" + filenameDict[software]
                            fullUrl = fullUrl.replace(versionDict[software], str(nvcheckDict[software]))
                            print(fullUrl)
                            dfp.envs[software + "_SHA256"] = get_remote_sha(fullUrl)

                        updated = True
                except KeyError as e:
                    print(software + " was not found in either " + versionFileName + " or " + dockerFileName)

        if updated:
            print(dockerFileName + " has been updated!")
        else:
            print("No update necessary for " + dockerFileName)

except FileNotFoundError:
    print(dockerFileName + " not found, must be in the current working directory.")
    raise SystemExit
