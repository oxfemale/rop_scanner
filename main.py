#!/usr/bin/env python3
"""ROP Gadget Scanner – command-line interface.

Usage examples
--------------
Scan a 32-bit DLL with default settings (depth 5, auto-detect arch):

    python main.py kernel32.dll

Scan a 64-bit DLL and write results to a file:

    python main.py ntdll.dll --arch x64 --output gadgets.txt

Increase gadget depth to find longer chains:

    python main.py msvcrt.dll --depth 8
"""

import argparse
import sys

import pefile

from rop_scanner import scan_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rop_scanner",
        description="ROP Gadget Scanner – find ROP gadgets inside Windows DLLs",
    )
    parser.add_argument(
        "file",
        help="Path to the target PE file (DLL or EXE)",
    )
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=5,
        metavar="N",
        help="Maximum number of instructions per gadget (default: 5)",
    )
    parser.add_argument(
        "--arch", "-a",
        choices=["auto", "x86", "x64"],
        default="auto",
        help="Target architecture; 'auto' reads it from the PE header (default: auto)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write gadgets to FILE instead of stdout",
    )
    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        gadgets = scan_file(args.file, max_gadget_depth=args.depth, arch=args.arch)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    except pefile.PEFormatError as exc:
        print(f"error: not a valid PE file: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    lines = [f"Found {len(gadgets)} unique gadget(s) in '{args.file}'"]
    lines += [str(g) for g in gadgets]
    output_text = "\n".join(lines) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output_text)
        except OSError as exc:
            print(f"error: cannot write output file: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
