#!/usr/bin/env bash
#
# System-wide install for ruuid: pip-installs the package into the
# system Python (so root finds the `ruuid` binary for `anchor` on
# privileged ports 53/443) and installs the man page.
#
# Run as root (e.g. via `sudo make install-global`).
#
# Demo-only setup (self-signed cert, /etc/hosts entry) lives in
# `demo/setup-demo.sh`; invoke that separately if you intend to run
# the bundled demo.
#
# pip's --break-system-packages sounds dramatic, but the actual
# consequence is "you've installed a Python package into the system
# site-packages directory" — which could collide with a future
# distro-packaged ruuid (unlikely).

set -e -u

if [ "$(id -u)" -ne 0 ]; then
    echo "error: install-global must be run with sudo" >&2
    echo "  try: sudo make install-global" >&2
    exit 1
fi

PYTHON=${PYTHON:-python3}
HERE=$(dirname "$0")

"$PYTHON" -m pip install \
    --break-system-packages --root-user-action=ignore .

# Install the man page; mandb on Fedora indexes /usr/local/share/man.
if [ -f "$HERE/../man/ruuid.1" ]; then
    install -D -m 0644 "$HERE/../man/ruuid.1" \
        /usr/local/share/man/man1/ruuid.1
    command -v mandb >/dev/null && mandb -q 2>/dev/null || true
    echo "installed man page (run: man ruuid)"
fi
