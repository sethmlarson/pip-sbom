import datetime
import io

from spdx.checksum import Checksum, ChecksumAlgorithm
from spdx.document import Document
from spdx.license import License
from spdx.package import ExternalPackageRef, Package, PackagePurpose
from spdx.version import Version
from spdx.writers.json import write_document

from ..._version import __version__
from ..dists import PackageDistInfo


def make_spdx_id(value: str) -> str:
    return f"SPDXRef-{value}"


hashlib_to_checksum_alg = {
    # TODO: Add all supported hash algorithms.
    "sha256": ChecksumAlgorithm.SHA256,
}


class SpdxJsonFormatter:
    def format(self, dist_infos: list[PackageDistInfo]) -> str:
        document = Document()
        document.name = "UNSET"
        document.namespace = "UNSET"
        document.spdx_id = "SPDXRef-DOCUMENT"
        document.version = Version("2", "3")
        document.data_license = License.from_identifier("CC0-1.0")

        document.creation_info.add_creator(
            f"Tool: pip-sbom/{__version__} (DO NOT USE IN PRODUCTION)"
        )
        document.creation_info.created = datetime.datetime.now(tz=datetime.UTC)

        for dist_info in dist_infos:
            package = Package(
                name=dist_info.name,
                version=dist_info.version,
            )
            package.spdx_id = make_spdx_id(f"Package-{package.name}-{package.version}")
            package.primary_package_purpose = PackagePurpose.LIBRARY

            # Pull information from the dist contained in the provenance_info.json
            if dist_info.provenance_url:
                provenance_url = dist_info.provenance_url
                hashes = provenance_url["archive_info"]["hashes"]

                # Set the download URL for the distribution.
                package.download_location = provenance_url["url"]

                # Add all available checksums.
                for alg_name, value in sorted(hashes.items()):
                    if alg_name not in hashlib_to_checksum_alg:
                        continue
                    package.set_checksum(
                        Checksum(
                            identifier=hashlib_to_checksum_alg[alg_name], value=value
                        )
                    )

                # Downloaded from PyPI means we can reference the package on PyPI via PURL.
                if package.download_location.startswith(
                    "https://files.pythonhosted.org/"
                ):
                    package.add_pkg_ext_refs(
                        ExternalPackageRef(
                            category="PACKAGE-MANAGER",
                            pkg_ext_ref_type="purl",
                            locator=f"pkg:pypi/{package.name}@{dist_info.version}",
                        )
                    )
            else:
                package.download_location = "NOASSERTION"

            document.add_package(package)

        out = io.StringIO()
        write_document(document, out)
        return out.getvalue()
