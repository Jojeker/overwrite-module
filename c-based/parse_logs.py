"""
Parse a dump from a unisoc modem
"""

#!/usr/bin/env python3
import re
import struct
import sys

# Match C-style printf specifiers and capture the type character
# Supports: %d, %i, %u, %x, %X, %p, %s (with width/flags)
SPEC_RE = re.compile(rb"%(?:\d+\$)?[#0\- +]*\d*(?:\.\d+)?([diuxXps])")


def is_printable_byte(b: int) -> bool:
    # Allow standard printable ASCII and space
    return 32 <= b < 127


def read_cstring(buf: bytes, offset: int, max_len: int = 256) -> str | None:
    i = offset
    min_len = 2
    n = len(buf)
    while i < n:
        if is_printable_byte(buf[i]):
            start = i
            while i < n and is_printable_byte(buf[i]):
                i += 1

            # Bail out on % (we hit a new fstting)
            if buf[i] == b"%":
                return None, 0, 0

            if i < n and buf[i] == 0x00:
                if i - start >= min_len:
                    out = buf[start:i]
                    return out.decode("ascii", errors="replace"), i + 1, start

            i += 1
        else:
            i += 1

    return None, 0, 0


def find_candidate_strings(buf: bytes, min_len: int = 4):
    i = 0
    n = len(buf)
    while i < n:
        if is_printable_byte(buf[i]):
            start = i
            while i < n and is_printable_byte(buf[i]):
                i += 1
            # Require a terminating NUL to consider it a proper C-string
            if i < n and buf[i] == 0x00:
                # Or no '%' to treat as format string
                if i - start >= min_len:  # and b"%" in buf[start:i]:
                    yield start, i, i  # start, end (exclusive), nul idx
            # Skip the NUL if present
            i += 1
        else:
            i += 1


def parse_numeric_args_after(buf: bytes, string_end: int, nargs: int):
    args: list[int] = []
    for i in range(nargs):
        pos = string_end + 8 + 8 * i
        if pos < 0 or pos + 4 > len(buf):
            args.append(0)
            continue
        (val,) = struct.unpack_from("<I", buf, pos)
        args.append(val)
    return args


def build_args_for_specs(
    buf: bytes,
    specs: list[str],
    string_end: int,
    nul_idx: int,
    used_string_starts: set[int],
):
    """
    Combine numeric args (from AFTER the string) and %s args (inline AFTER
    the string) into a single argument list in printf order.

    - Numeric specs (d, i, u, x, X, p) -> 32-bit
    - %s specs -> next C-string
    """
    # Count numeric specs (anything except 's')
    numeric_specs = [s for s in specs if s != "s"]
    numeric_n = len(numeric_specs)

    # Read numeric args before the format string
    numeric_args = parse_numeric_args_after(buf, string_end, numeric_n)
    numeric_idx = 0

    # Cursor for scanning inline %s argument strings after the format
    cursor = nul_idx + 1

    args: list[object] = []

    for spec in specs:
        if spec == "s":
            # Find next usable string after the format
            s, cursor, s_start = read_cstring(buf, cursor)
            if s is None:
                s = "<string>"
            else:
                if s_start is not None:
                    used_string_starts.add(s_start)

            args.append(s)
        else:
            # Use next numeric arg
            if numeric_idx < len(numeric_args):
                args.append(numeric_args[numeric_idx])
                numeric_idx += 1
            else:
                args.append(0)

    return args


def format_log(fmt: str, args):
    """
    Try to apply C-style %-formatting with the constructed arguments.
    On mismatch, fall back to showing raw args.
    """
    try:
        return fmt % tuple(args)
    except Exception:
        arg_str = " ".join(repr(a) for a in args)
        return f"{fmt}  [ARGS: {arg_str}]"


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "-":
        data = sys.stdin.buffer.read()
        source = "<stdin>"
    else:
        with open(sys.argv[1], "rb") as f:
            data = f.read()
        source = sys.argv[1]

    used_string_starts: set[int] = set()

    for start, end, nul_idx in find_candidate_strings(data):
        fmt_bytes = data[start:end]
        fmt_str = fmt_bytes.decode("ascii", errors="replace")

        # Extract specifiers and their types in order
        specs = [m.group(1).decode("ascii") for m in SPEC_RE.finditer(fmt_bytes)]

        if not specs:
            # Plain string; skip if we already used it as a %s argument
            if start in used_string_starts:
                continue
            print(f"{source}:0x{start:08X}: {fmt_str}")
            continue

        args = build_args_for_specs(data, specs, end, nul_idx, used_string_starts)
        log_line = format_log(fmt_str, args)

        print(f"{source}:0x{start:08X}: {log_line}")


if __name__ == "__main__":
    main()
