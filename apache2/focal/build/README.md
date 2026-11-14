# Focal source acquisition (workstation/test VM only)

Run inside a clean Ubuntu 20.04 Focal build VM/container with matching source repositories enabled, as an ordinary user with sudo available for package metadata operations:

```sh
sudo apt-get update
apt-cache showsrc apache2 | sed -n '1,80p'
mkdir -p ~/apache2-backport && cd ~/apache2-backport
apt-get source apache2=2.4.41-4ubuntu3.23
```

**Do not run these commands on the production web server**, and do not add third-party repositories to solve missing sources. If `apt-get source` reports missing `deb-src` entries, configure official Focal source repositories in the isolated build environment. `apt-get source` does not install the package or modify Apache.

Next: record retrieved source .dsc provenance/checksums, inspect `debian/patches/series`, list applicable CVEs from Focal's standard-update baseline through current ESM and assess whether official ESM source can legally/technically be accessed. Only then select patch candidates. No backport is currently validated.
