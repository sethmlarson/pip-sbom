"""Discover the installed packages and their metadata in the environment"""
import email
import json
import os
import typing
from dataclasses import dataclass

from packaging.utils import canonicalize_name
from packaging.version import Version


@dataclass
class PackageDistInfo:
    name: str
    version: str
    provenance_url: None | dict[str, typing.Any]


def get_package_dist_info(dist_info_dir: str, /) -> PackageDistInfo | None:
    try:
        # This is how importlib.metadata parses the METADATA file:
        with open(os.path.join(dist_info_dir, "METADATA")) as f:
            metadata = email.message_from_file(f)
    except OSError:
        return None

    name = metadata.get("Name", None)
    if name is not None:
        name = canonicalize_name(name)
    else:
        print(f"No package name found in METADATA for {dist_info_dir}")
        return None

    version = metadata.get("Version", None)
    if version is None:
        print(f"No package version found in METADATA for {dist_info_dir}")
        return None

    # provenance_url.json file is defined in PEP 710.
    provenance_url = None
    try:
        with open(os.path.join(dist_info_dir, "provenance_url.json")) as f:
            provenance_url = json.load(f)
    except FileNotFoundError:
        pass

    return PackageDistInfo(name=name, version=version, provenance_url=provenance_url)


def get_package_dist_infos(site_packages: list[str], /) -> list[PackageDistInfo]:
    package_dist_infos = []
    for site_package in site_packages:
        try:
            potential_dist_infos = sorted(os.listdir(site_package))
        except OSError as e:
            print(f"Not a directory: {site_package} {e}")
            continue

        for potential_dist_info in potential_dist_infos:
            if not potential_dist_info.endswith(".dist-info"):
                continue
            dist_info_dir = os.path.join(site_package, potential_dist_info)

            if package_dist_info := get_package_dist_info(dist_info_dir):
                package_dist_infos.append(package_dist_info)

    return sorted(package_dist_infos, key=lambda pdi: (pdi.name, Version(pdi.version)))
