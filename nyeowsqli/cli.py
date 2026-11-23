"""Command-line entry point for NYEOWSQLiSCANNER."""

from . import TOOL_NAME, __version__


def main(argv=None):
    print(f"{TOOL_NAME} v{__version__}")
    return 0
