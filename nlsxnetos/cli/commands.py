"""CLI command definitions."""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="nlsxnetos")
    parser.add_argument("--version", action="version", version="nlsxnetos 0.1.0")
    parser.parse_args()
