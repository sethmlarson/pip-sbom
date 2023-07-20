import datetime
import io

from packageurl import PackageURL
from spdx.checksum import Checksum, ChecksumAlgorithm
from spdx.document import Document
from spdx.license import License
from spdx.package import ExternalPackageRef, Package, PackagePurpose
from spdx.version import Version
from spdx.writers.json import write_document

from ..._version import __version__
from ..sources.dist_info import PackageDistInfo


def make_spdx_id(value: str) -> str:
    return f"SPDXRef-{value}"


hashlib_to_checksum_alg = {
    # TODO: Add more supported hash algorithms.
    "sha224": ChecksumAlgorithm.SHA224,
    "sha256": ChecksumAlgorithm.SHA256,
    "sha512": ChecksumAlgorithm.SHA512,
    "sha3_256": ChecksumAlgorithm.SHA3_256,
    "sha3_384": ChecksumAlgorithm.SHA3_384,
    "sha3_512": ChecksumAlgorithm.SHA3_512,
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

            if dist_info.download_url:
                # Set the download URL for the distribution.
                package.download_location = dist_info.download_url

                # Downloaded from PyPI means we can reference the package on PyPI via PURL.
                if (
                    dist_info.download_url.startswith("https://files.pythonhosted.org/")
                    # Avoid URL authority shenanigans, PyPI doesn't need authentication to download
                    # and is likely the highest value target for masquerading as an existing project.
                    and "@" not in dist_info.download_url
                ):
                    package.add_pkg_ext_refs(
                        ExternalPackageRef(
                            category="PACKAGE-MANAGER",
                            pkg_ext_ref_type="purl",
                            locator=PackageURL(
                                type="pkg",
                                namespace="pypi",
                                name=dist_info.name,
                                version=dist_info.version,
                            ).to_string(),
                        )
                    )
            else:
                package.download_location = "NOASSERTION"

            # Add all available checksums.
            if dist_info.hashes:
                for alg_name, value in sorted(dist_info.hashes.items()):
                    if alg_name not in hashlib_to_checksum_alg:
                        continue
                    package.set_checksum(
                        Checksum(
                            identifier=hashlib_to_checksum_alg[alg_name], value=value
                        )
                    )

            document.add_package(package)

        out = io.StringIO()
        write_document(document, out)
        return out.getvalue()
