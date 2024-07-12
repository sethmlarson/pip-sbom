import datetime
import io
import re
import uuid

from packageurl import PackageURL
from spdx_tools.spdx.model import (
    Document,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
)
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackagePurpose,
)
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream

from ..._version import __version__
from ..sources.dist_info import PackageDistInfo

hashlib_to_checksum_alg = {
    "md5": ChecksumAlgorithm.MD5,
    "sha1": ChecksumAlgorithm.SHA1,
    "sha224": ChecksumAlgorithm.SHA224,
    "sha256": ChecksumAlgorithm.SHA256,
    "sha512": ChecksumAlgorithm.SHA512,
    "sha3_256": ChecksumAlgorithm.SHA3_256,
    "sha3_384": ChecksumAlgorithm.SHA3_384,
    "sha3_512": ChecksumAlgorithm.SHA3_512,
}


class BaseSpdxJsonFormatter:
    @staticmethod
    def make_spdx_id(value: str) -> str:
        return f"SPDXRef-{re.sub(r'[^a-zA-Z0-9.-]+', '-', value)}"


class Spdx2JsonFormatter(BaseSpdxJsonFormatter):
    def format(self, dist_infos: list[PackageDistInfo]) -> str:
        document_spdx_id = "SPDXRef-DOCUMENT"
        document = Document(
            creation_info=CreationInfo(
                spdx_id=document_spdx_id,
                name="UNSET",
                document_namespace=f"{uuid.uuid4().urn}",
                spdx_version="SPDX-2.3",
                created=datetime.datetime.now(tz=datetime.UTC),
                data_license="CC0-1.0",
                creators=[
                    Actor(
                        ActorType.TOOL,
                        name=f"pip-sbom/{__version__} (DO NOT USE IN PRODUCTION)",
                    )
                ],
            )
        )

        for dist_info in dist_infos:
            package_spdx_id = self.make_spdx_id(
                f"Package-{dist_info.name}-{dist_info.version}"
            )

            # Set the download URL for the distribution.
            if dist_info.download_url:
                download_location = dist_info.download_url
            else:
                download_location = SpdxNoAssertion()

            package = Package(
                name=dist_info.name,
                version=dist_info.version,
                spdx_id=package_spdx_id,
                download_location=download_location,
                primary_package_purpose=PackagePurpose.LIBRARY,
            )

            # Downloaded from PyPI means we can reference the package on PyPI via PURL.
            if dist_info.is_from_pypi():
                package.external_references.append(
                    ExternalPackageRef(
                        category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                        reference_type="purl",
                        locator=PackageURL(
                            type="pypi",
                            name=dist_info.name,
                            version=dist_info.version,
                        ).to_string(),
                    )
                )

            # Add all available checksums.
            if dist_info.hashes:
                for alg_name, value in sorted(dist_info.hashes.items()):
                    if alg_name not in hashlib_to_checksum_alg:
                        continue
                    package.checksums.append(
                        Checksum(
                            algorithm=hashlib_to_checksum_alg[alg_name], value=value
                        )
                    )

            document.packages.append(package)
            document.relationships.append(
                Relationship(
                    spdx_element_id=document_spdx_id,
                    relationship_type=RelationshipType.DESCRIBES,
                    related_spdx_element_id=package_spdx_id,
                )
            )

        out = io.StringIO()
        write_document_to_stream(document, out)
        return out.getvalue()
