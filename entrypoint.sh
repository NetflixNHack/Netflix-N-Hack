#!/bin/sh
set -e

# Usage:
#  entrypoint.sh ps4         -> run PS4 proxy (default)
#  entrypoint.sh ps5         -> run PS5 proxy
#  entrypoint.sh [mitmdump args...] -> pass args directly to mitmdump

if [ "$#" -gt 0 ]; then
  case "$1" in
    ps5)
      shift
      exec mitmdump -p "${MITM_PORT:-8080}" -s PS5/proxy.py "$@"
      ;;
    ps4)
      shift
      exec mitmdump -p "${MITM_PORT:-8080}" -s PS4/proxy.py "$@"
      ;;
    *)
      # Pass-through: treat provided args as mitmdump arguments
      exec mitmdump "$@"
      ;;
  esac
else
  # Default to PS4 proxy (port configurable via MITM_PORT)
  exec mitmdump -p "${MITM_PORT:-8080}" -s PS4/proxy.py
fi
