#!/usr/bin/env python3
"""Print the saved Monarch session so it can be stored as a hosted secret.

Run login_setup.py first, then pipe this straight into your secret store, for
example Google Secret Manager:

    python export_session.py | gcloud secrets create monarch-session --data-file=-

The server reads the value back from the MONARCH_MCP_SESSION environment
variable. The output is a live credential with full access to your Monarch
account, so this refuses to write it to a terminal unless --show is given:
it should go into a pipe, not your scrollback.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from monarch_mcp_server.secure_session import secure_session  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--show",
        action="store_true",
        help="print to the terminal even though stdout is not redirected",
    )
    args = parser.parse_args()

    session = secure_session.load_session()
    if not session:
        print(
            "No saved Monarch session found. Run: python login_setup.py",
            file=sys.stderr,
        )
        return 1

    if sys.stdout.isatty() and not args.show:
        print(
            "Refusing to print a live Monarch credential to the terminal. "
            "Pipe it into your secret store instead, for example:\n"
            "  python export_session.py | gcloud secrets create "
            "monarch-session --data-file=-\n"
            "or pass --show if you really want to see it.",
            file=sys.stderr,
        )
        return 2

    sys.stdout.write(json.dumps(session))
    return 0


if __name__ == "__main__":
    sys.exit(main())
