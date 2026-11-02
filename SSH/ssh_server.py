#!/usr/bin/env python3
"""Migration guidance for the retired SSH-only entrypoint."""
import sys


def main() -> int:
    print("Use 'deceive config migrate SSH/config.ini --output-dir migrated', then "
          "'deceive serve --config migrated/deployment.yaml'. See README.md.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
