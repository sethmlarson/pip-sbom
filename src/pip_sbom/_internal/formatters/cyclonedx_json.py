import datetime
import json

from cyclonedx.model import (
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Tool,
    XsUri,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import OutputFormat, SchemaVersion
from cyclonedx.output import get_instance as get_output_instance
from packageurl import PackageURL

from ..._version import __version__
from ..sources.dist_info import PackageDistInfo

hashlib_to_checksum_alg = {
    "sha256": HashAlgorithm.SHA_256,
    "sha512": HashAlgorithm.SHA_512,
    "sha3_256": HashAlgorithm.SHA3_256,
    "sha3_384": HashAlgorithm.SHA3_384,
    "sha3_512": HashAlgorithm.SHA3_512,
}


class CycloneDxJsonFormatter:
    def format(self, dist_infos: list[PackageDistInfo]) -> str:
        bom = Bom()
        bom.metadata.tools.add(
            Tool(
                name="pip-sbom",
                version=f"{__version__} (DO NOT USE IN PRODUCTION)",
            )
        )
        bom.metadata.timestamp = datetime.datetime.now(tz=datetime.UTC)

        for dist_info in dist_infos:
            component = Component(
                name=dist_info.name,
                version=dist_info.version,
                type=ComponentType.LIBRARY,
            )

            if dist_info.download_url:
                # Set the download URL for the distribution.
                component.external_references.add(
                    ExternalReference(
                        type=ExternalReferenceType.DISTRIBUTION,
                        url=XsUri(dist_info.download_url),
                    )
                )

                # Downloaded from PyPI means we can reference the package on PyPI via PURL.
                if (
                    dist_info.download_url.startswith("https://files.pythonhosted.org/")
                    # Avoid URL authority shenanigans, PyPI doesn't need authentication to download
                    # and is likely the highest value target for masquerading as an existing project.
                    and "@" not in dist_info.download_url
                ):
                    component.purl = PackageURL(
                        type="pkg",
                        namespace="pypi",
                        name=dist_info.name,
                        version=dist_info.version,
                    )

            # Add all available checksums.
            if dist_info.hashes:
                for alg_name, value in sorted(dist_info.hashes.items()):
                    if alg_name not in hashlib_to_checksum_alg:
                        continue
                    component.hashes.add(
                        HashType(
                            alg=hashlib_to_checksum_alg[alg_name],
                            content=value,
                        )
                    )

            bom.components.add(component)

        output = get_output_instance(
            bom=bom, output_format=OutputFormat.JSON, schema_version=SchemaVersion.V1_4
        )
        return json.dumps(json.loads(output.output_as_string()), indent=2)
