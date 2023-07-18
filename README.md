# pip-sbom

Generate Software Bill-of-Materials (SBOMs) for Python environments from distribution metadata.

> **Warning**: This project is highly experimental and should not be used in production.

## Usage

This tool requires packages to be installed with a PEP 710-compliant installer in order to provide
the complete set of fields in an SBOM like checksums, installation URLs, and external references.

By default will search for installed packages in the current Python installation. 

```shell
$ python -m pip install git+https://github.com/sethmlarson/pip-sbom
$ pip-sbom
```

This will output a JSON SPDX document that looks like this:

```json
{
    "spdxVersion": "SPDX-2.3",
    "documentNamespace": "UNSET",
    "creationInfo": {
        "creators": [
            "Tool: pip-sbom/0.0.1a2 (DO-NOT-USE-IN-PRODUCTION)"
        ],
        "created": "2023-07-18T19:40:33.092083+00:00Z",
        "licenseListVersion": "3.20"
    },
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "UNSET",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-packaging-23.1",
            "name": "packaging",
            "downloadLocation": "https://files.pythonhosted.org/packages/ab/c3/57f0601a2d4fe15de7a553c00adbc901425661bf048f2a22dfc500caf121/packaging-23.1-py3-none-any.whl",
            "versionInfo": "23.1",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": "994793af429502c4ea2ebf6bf664629d07c1a9fe974af92966e4b8d2df7edc61"
                }
            ],
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/packaging@23.1"
                }
            ]
        },
        ...
    ]
}
```

## License

MIT
