#!/usr/bin/env python3
import re
import sys

from os import listdir
from os.path import isfile, join
from datetime import timedelta

# Matches:
# 2979  01:49:00.262734 write(19<...>, "\x0d", 1) = 1
# PID TIME
PREFIX = r'^(?:\[\w+\]\s+)?(?:(\d+)\s+)?(\d{2}:\d{2}:\d{2}\.\d+\s+)?'

# FD PATH ARG2 LEN RETVAL
WRITE_RE = re.compile(PREFIX + r'write(?:64)?\((\d+)[^,]*,\s+(".*?"|0x[0-9a-fA-F]+),\s+(\d+)\)\s+=\s+(-?\d+)')
READ_RE  = re.compile(PREFIX + r'read(?:64)?\((\d+)[^,]*,\s+(".*?"|0x[0-9a-fA-F]+),\s+(\d+)\)\s+=\s+(-?\d+)')
FD_ANN_RE = re.compile(r'\((\d+)<([^>]*)>')

# Find a hex-escaped absolute path starting with \x2f (= '/')
HEXPATH_RE = re.compile(r'(\\x2f(?:\\x[0-9a-fA-F]{2})+)')

def decode_strace_hex_escapes(s: str) -> bytes:
    # s like: \x2f\x64\x65\x76\x2f...
    out = bytearray()
    i = 0
    while i < len(s):
        if s.startswith(r'\x', i) and i + 3 < len(s):
            out.append(int(s[i+2:i+4], 16))
            i += 4
        else:
            # should not happen for HEXPATH_RE matches, but keep safe
            out.append(ord(s[i]))
            i += 1
    return bytes(out)

def decode_strace_string_literal(arg: str) -> bytes | None:
    # arg is either "...." (with \xNN) or a pointer 0x...
    if not (arg.startswith('"') and arg.endswith('"')):
        return None
    inner = arg[1:-1]
    # Only decode \xNN plus common escapes; keep everything else literal.
    out = bytearray()
    i = 0
    while i < len(inner):
        c = inner[i]
        if c != '\\':
            out.append(ord(c)); i += 1; continue
        i += 1
        if i >= len(inner):
            out.append(ord('\\')); break
        e = inner[i]; i += 1
        if e == 'x' and i + 1 < len(inner):
            hx = inner[i:i+2]
            if len(hx) == 2 and all(ch in "0123456789abcdefABCDEF" for ch in hx):
                out.append(int(hx, 16))
                i += 2
            else:
                out.extend(b'\\x')
        elif e == 'n': out.append(0x0A)
        elif e == 'r': out.append(0x0D)
        elif e == 't': out.append(0x09)
        elif e == '\\': out.append(0x5C)
        elif e == '"': out.append(0x22)
        else:
            # keep unknown escape literally
            out.append(ord('\\'))
            out.append(ord(e))
    return bytes(out)

def bytes_to_ascii(b: bytes) -> str:
    return ''.join(chr(x) if 32 <= x <= 126 else '.' for x in b)

def extract_dev_path_from_line(line: str) -> str | None:
    m = FD_ANN_RE.search(line)
    if not m:
        return None
    ann = m.group(2)  # inside <...>
    hp = HEXPATH_RE.search(ann)
    if not hp:
        return None
    path_bytes = decode_strace_hex_escapes(hp.group(1))
    try:
        path = path_bytes.decode('ascii', errors='strict')
    except UnicodeDecodeError:
        return None
    return path if path.startswith("/dev/s") else None

def parse_rel_time(ts):
    h,m,s = ts.split(":")
    s,f = s.split(".")
    hours=int(h) * 3600 * 1000
    minutes=int(m) * 60 * 1000
    seconds=int(s) * 1000
    milliseconds=int(f)

    return hours + minutes + seconds + milliseconds



def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <strace log dir>", file=sys.stderr)
        sys.exit(2)
    
    log_files = [join(sys.argv[1],f) for f in listdir(sys.argv[1]) if isfile(join(sys.argv[1], f))]
    # All entries
    GLOB_LOGS = {}

    for log in log_files:

        with open(log, "r", errors="replace") as f:

            for line in f:
                line = line.rstrip("\n")

                path = extract_dev_path_from_line(line)
                if not path:
                    continue  # ignore UNIX sockets etc.

                m = WRITE_RE.match(line)
                if m:
                    pid, time, fd_s, arg2, _count, ret_s = m.groups()
                    to = parse_rel_time(time)
                    if int(ret_s) <= 0:
                        continue
                    payload = decode_strace_string_literal(arg2)
                    if payload is None:
                        continue

                    if GLOB_LOGS.get(to) is None:
                        GLOB_LOGS.update({str(to): []})

                    GLOB_LOGS[str(to)].append({ "type": "w", "payl": payload.hex(), "ascii": bytes_to_ascii(payload), "path": path})
                    # print(f"WRITE\t{path}\t{payload.hex()}\t{bytes_to_ascii(payload)}")
                    continue

                m = READ_RE.match(line)
                if m:
                    pid, time, fd_s, arg2, _count, ret_s = m.groups()
                    if int(ret_s) <= 0:
                        continue
                    payload = decode_strace_string_literal(arg2)
                    if payload is None:
                        continue
                    # print(f"READ\t{path}\t{payload.hex()}\t{bytes_to_ascii(payload)}")

                    if GLOB_LOGS.get(to) is None:
                        GLOB_LOGS.update({str(to): []})

                    GLOB_LOGS[str(to)].append({ "type": "r", "payl": payload.hex(), "ascii": bytes_to_ascii(payload), "path": path})
                    # print(f"READ\t{path}\t{payload.hex()}\t{bytes_to_ascii(payload)}")

                    continue

    min_key = min(int(k) for k,v in GLOB_LOGS.items())

    GLOB_LOGS = {
        str(int(k) - min_key): v
        for k, v in GLOB_LOGS.items()
    }


    # Sort by time
    GLOB_LOGS = dict(sorted(GLOB_LOGS.items(), key=lambda x: int(x[0])))

    for i in GLOB_LOGS.items():
        print(i)

if __name__ == "__main__":
    main()

