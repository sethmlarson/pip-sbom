import argparse
import os
import site
import sys

from packaging.version import Version

from .formatters.cyclonedx_json import CycloneDxJsonFormatter
from .formatters.spdx_json import SpdxJsonFormatter
from .sources import pep710, pip_report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser("pip-sbom")
    parser.add_argument("--source", default="env", choices=["env", "pip"])
    parser.add_argument("--sbom-format", default="spdx", choices=["spdx", "cyclonedx"])
    parser.add_argument("--format", default="json", choices=["json"])
    parser.add_argument(
        "--site-packages", default=os.pathsep.join(site.getsitepackages())
    )

    # Remove arguments after '--' for use with the pip input.
    post_argv = []
    try:
        dashes_in_argv = argv.index("--")
    except ValueError:
        dashes_in_argv = -1
    if dashes_in_argv != -1:
        post_argv = argv[dashes_in_argv + 1 :]
        argv = argv[:dashes_in_argv]

    # Parse the passed arguments.
    parsed = parser.parse_args(argv)

    # Ensure that '--' is used consistently.
    if dashes_in_argv != -1 and parsed.source != "pip":
        print("Using '--' in the pip-sbom command is only allowed with --source=pip")
        return 1
    elif dashes_in_argv == -1 and parsed.source == "pip":
        print("Must pass additional parameters after '--' when using --source=pip")
        print(
            "These arguments are passed to 'pip install' (ie 'pip-sbom --source=pip -- -r requirements.txt')"
        )
        return 1

    # Gather distribution information from sources.
    if parsed.source == "pip":
        dist_infos, returncode = pip_report.get_dist_infos(post_argv)
    elif parsed.source == "env":
        site_packages = parsed.site_packages.split(os.pathsep)
        dist_infos, returncode = pep710.get_dist_infos(site_packages)
    else:
        print("Unknown --source value, must be either 'pip' or 'env'")
        return 1

    # If gathering the distribution information failed we exit with
    # the code given to us by the gathering function.
    if returncode:
        return returncode

    # Sort the results so they appear consistently when rendered.
    dist_infos = sorted(dist_infos, key=lambda pdi: (pdi.name, Version(pdi.version)))

    if not dist_infos:
        print("Didn't find any distribution information from source")
        return 1

    if parsed.sbom_format == "spdx":
        formatter = SpdxJsonFormatter()
    elif parsed.sbom_format == "cyclonedx":
        formatter = CycloneDxJsonFormatter()
    else:
        print("Unknown --sbom-format value, must be one of 'spdx' or 'cyclonedx'")
        return 1

    print(formatter.format(dist_infos))
    return 0


def cli():
    # Entry-point for the pip-sbom CLI.
    sys.exit(main(sys.argv[1:]))
