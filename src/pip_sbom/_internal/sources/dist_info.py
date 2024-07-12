from dataclasses import dataclass


@dataclass
class PackageDistInfo:
    name: str
    version: str
    hashes: dict[str, str] | None = None
    download_url: str | None = None

    def is_from_pypi(self) -> bool:
        """Returns 'true' if the download URL is from PyPI"""
        return (
            self.download_url
            and self.download_url.startswith("https://files.pythonhosted.org/")
            # Avoid URL authority shenanigans, PyPI doesn't need authentication to download
            # and is likely the highest value target for masquerading as an existing project.
            and "@" not in self.download_url
        )
