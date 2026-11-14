#!/usr/bin/env python3
"""Fetch and SHA256-verify public PHP Focal release packages for disposable CI."""
import hashlib
import json
import pathlib
import sys
import urllib.request

VERSIONS = {
    "8.3": "v8.3.36-focal.1",
    "8.4": "v8.4.27-focal.1",
}


def get(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": "apache-focal-compat-ci",
                      "Accept": "application/vnd.github+json"})
    return urllib.request.urlopen(req, timeout=90)


def download(url, target):
    with get(url) as response, open(target, "wb") as output:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            output.write(block)


def main(version, dest):
    tag = VERSIONS[version]
    root = pathlib.Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    with get("https://api.github.com/repos/bilo1967/php83-legacy/releases/tags/" + tag) as src:
        release = json.load(src)
    assets = release["assets"]
    by_name = {a["name"]: a["browser_download_url"] for a in assets}
    sha_file = root / "SHA256SUMS"
    if "SHA256SUMS" not in by_name:
        raise RuntimeError("Release lacks SHA256SUMS: " + tag)
    download(by_name["SHA256SUMS"], sha_file)
    checksums = {}
    for line in sha_file.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and len(fields[0]) == 64:
            checksums[pathlib.PurePosixPath(fields[1].removeprefix("*")).name] = fields[0].lower()

    packages = [
        "libapache2-mod-php" + version,
        "php" + version + "-common",
        "php" + version + "-cli",
        "php" + version + "-opcache",
    ]
    if version == "8.4":
        packages.append("php-common")
    for package in packages:
        names = [name for name in by_name if name.startswith(package + "_") and name.endswith(".deb")]
        if len(names) != 1:
            raise RuntimeError("Expected exactly one asset for " + package + ": " + str(names))
        name = names[0]
        if name not in checksums:
            raise RuntimeError("No checksum for " + name)
        target = root / name
        download(by_name[name], target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest.lower() != checksums[name]:
            raise RuntimeError("SHA256 mismatch for " + name)
        print("Verified", tag, name, flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in VERSIONS:
        sys.exit("Usage: fetch-legacy-php.py 8.3|8.4 OUTPUT_DIRECTORY")
    main(sys.argv[1], sys.argv[2])
