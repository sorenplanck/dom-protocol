#!/usr/bin/env python3
from __future__ import annotations
import argparse, os
from pathlib import Path

parser=argparse.ArgumentParser(description="Generate a 256-bit DOM XMR sidecar HMAC key")
parser.add_argument('path')
args=parser.parse_args()
path=Path(args.path).expanduser().resolve()
path.parent.mkdir(parents=True,exist_ok=True)
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
fd=os.open(path,flags,0o600)
try:
    with os.fdopen(fd,'w') as stream:
        stream.write(os.urandom(32).hex()+"\n")
finally:
    os.chmod(path,0o600)
print(path)
