#!/usr/bin/env bash
#
# Reverse install-global.sh: pip-uninstall ruuid from the system
# Python and remove /etc/ruuid/anchor-cert.pem (and the directory if
# it's empty).
#
# Run as root (e.g. via `sudo make uninstall-global`).

set -e -u

if [ "$(id -u)" -ne 0 ]; then
    echo "error: uninstall-global must be run with sudo" >&2
    echo "  try: sudo make uninstall-global" >&2
    exit 1
fi

PYTHON=${PYTHON:-python3}

"$PYTHON" -m pip uninstall \
    --break-system-packages --root-user-action=ignore -y ruuid

rm -f /etc/ruuid/anchor-cert.pem
rmdir /etc/ruuid 2>/dev/null || true

rm -f /usr/local/share/man/man1/ruuid.1
command -v mandb >/dev/null && mandb -q 2>/dev/null || true
