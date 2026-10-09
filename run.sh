#!/bin/sh
# Starts TwinShield on this machine. Needs Python 3.8+. No packages to install.
cd "$(dirname "$0")" && exec python3 -m twinshield serve "$@"
