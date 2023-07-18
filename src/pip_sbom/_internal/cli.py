import argparse
import os
import site
import sys

from .dists import get_package_dist_infos
from .formatters.spdx_json import SpdxJsonFormatter


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser("pip-sbom")
    parser.add_argument(
        "--site-packages", default=os.pathsep.join(site.getsitepackages())
    )
    parsed = parser.parse_args(argv)

    site_packages = parsed.site_packages.split(os.pathsep)
    dist_infos = get_package_dist_infos(site_packages)
    if not dist_infos:
        print(f"ERROR: Didn't find any .dist-info directories at {site_packages}")
        return 1

    formatter = SpdxJsonFormatter()
    print(formatter.format(dist_infos))
    return 0


def cli():
    # Entry-point for the pip-sbom CLI.
    sys.exit(main(sys.argv[1:]))
