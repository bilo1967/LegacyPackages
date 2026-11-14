# Apache 2.4 backport for Ubuntu 20.04 Focal

Status: **investigation; NOT RELEASE READY**.

Installed baseline on the two reported Focal hosts: `2.4.41-4ubuntu3.23` (amd64). `apache2-dev` is also installed.

Goals:
- Preserve Ubuntu Focal's `debian/` packaging, conffile handling, layout, and module integration.
- Establish the complete applicable CVE/USN list, including earlier ESM fixes, before selecting patches.
- Prefer verified vendor security patch provenance; do not assume patches from Jammy apply verbatim.
- Build reproducibly in an isolated Ubuntu 20.04 environment.
- Validate dependency relationships, ABI/module loading, Apache configuration, PHP integration, and regression behavior.

Pending host inventory (share outputs without secrets):

```sh
apache2 -v
apache2ctl -M
apache2ctl -V
a2query -M
dpkg-query -W 'apache2*' 'libapache2-mod-*' 'libnghttp2*' 'php*-fpm' 2>/dev/null
apt-cache policy apache2 apache2-bin apache2-dev
```

Do not deploy to production until full patch review, builds, and tests are documented.
