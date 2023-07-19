from dataclasses import dataclass


@dataclass
class PackageDistInfo:
    name: str
    version: str
    hashes: dict[str, str] | None = None
    download_url: str | None = None
