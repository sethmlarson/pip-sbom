"""Discover metadata from running '$ python -m pip install --report - XYZ'"""

import json
import subprocess
import sys

from packaging.utils import canonicalize_name

from .dist_info import PackageDistInfo


def get_dist_infos(pip_install_args: list[str]) -> tuple[list[PackageDistInfo], int]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--disable-pip-version-check",
            "--dry-run",
            "--ignore-installed",
            "--report",
            "-",
        ]
        + pip_install_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        print(proc.stderr.decode("utf-8"))
        return [], 1

    pip_report = json.loads(proc.stdout.decode("utf-8"))

    dist_infos = []
    for install_report in pip_report["install"]:
        name = canonicalize_name(install_report["metadata"]["name"])
        version = install_report["metadata"]["version"]

        download_url = install_report["download_info"]["url"]
        archive_info = install_report["download_info"].get("archive_info", {})

        # Hashes may not be available, like when installing a package from a directory.
        # In order to support the Direct URL spec we need to check both 'hashes' and 'hash'.
        hashes = None
        if "hashes" in archive_info:
            hashes = archive_info["hashes"]
        elif "hash" in archive_info:
            alg, value = archive_info["hash"].split("=", 1)
            hashes = {alg: value}

        dist_infos.append(
            PackageDistInfo(
                name=name, version=version, hashes=hashes, download_url=download_url
            )
        )

    return dist_infos, 0
