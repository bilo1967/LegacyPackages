#!/usr/bin/env python3
"""Fetch public PHP Focal release .deb assets and verify GitHub SHA256 digests."""
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.request

RELEASES = {
    "8.3": "v8.3.36-focal.1",
    "8.4": "v8.4.27-focal.1",
}
REPO_API = "https://api.github.com/repos/bilo1967/php83-legacy/releases/tags/"


def get(url):
    headers = {"User-Agent": "apache-focal-compat-ci"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        else:
            raise RuntimeError("GH_TOKEN required for GitHub API release metadata")
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=90)


def load_assets(tag):
    with get(REPO_API + tag) as response:
        release = json.load(response)
    # These trusted Focal packages are deliberately published as prereleases.
    # The API/tag and exact .deb names identify the requested build.
    if release.get("draft"):
        raise RuntimeError("Release is still a draft: " + tag)
    return {asset["name"]: asset for asset in release["assets"]}


def download_verified(assets, package, dest, release_tag):
    matching = [
        item for name, item in assets.items()
        if name.startswith(package + "_") and name.endswith(".deb")
    ]
    if len(matching) != 1:
        raise RuntimeError("Expected exactly one %s package in %s: %s" %
                           (package, release_tag,
                            [a["name"] for a in matching]))
    asset = matching[0]
    digest = asset.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise RuntimeError("GitHub release asset has no valid SHA256: " + asset["name"])
    output_path = dest / asset["name"]
    hasher = hashlib.sha256()
    with get(asset["browser_download_url"]) as response, output_path.open("wb") as output:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            hasher.update(block)
            output.write(block)
    if hasher.hexdigest().lower() != digest[7:].lower():
        output_path.unlink(missing_ok=True)
        raise RuntimeError("GitHub release SHA256 mismatch: " + asset["name"])
    print("SHA256 verified:", release_tag, asset["name"], flush=True)


def main(version, destination):
    dest = pathlib.Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    release_tag = RELEASES[version]
    assets = load_assets(release_tag)
    for package in (
        "libapache2-mod-php" + version,
        "php" + version + "-common",
        "php" + version + "-cli",
        "php" + version + "-readline",  # Required by the versioned CLI package.
        "php" + version + "-opcache",
        "php" + version + "-fpm",
    ):
        download_verified(assets, package, dest, release_tag)

    # PHP 8.4 bundles an updated php-common compatible with both
    # Focal PHP 8.x package sets; the stock Focal package is too old.
    common_tag = RELEASES["8.4"]
    common_assets = assets if version == "8.4" else load_assets(common_tag)
    download_verified(common_assets, "php-common", dest, common_tag)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in RELEASES:
        sys.exit("Usage: fetch-legacy-php.py 8.3|8.4 OUTPUT_DIRECTORY")
    main(sys.argv[1], sys.argv[2])
