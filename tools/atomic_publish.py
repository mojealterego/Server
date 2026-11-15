#!/usr/bin/env python3
"""Atomic no-overwrite directory publication on Linux, renameat2 RENAME_NOREPLACE.
Fails closed on unsupported platform and when destination exists.
"""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import sys

AT_FDCWD=-100
RENAME_NOREPLACE=1

def publish(source:Path,target:Path)->None:
    if source.is_symlink() or not source.is_dir():raise ValueError('Invalid source directory')
    if target.exists() or target.is_symlink():raise FileExistsError(str(target))
    if os.uname().sysname!='Linux':raise OSError('Atomic no-replace rename requires Linux')
    libc=ctypes.CDLL(None,use_errno=True)
    if not hasattr(libc,'renameat2'):
        raise OSError('renameat2 unavailable: refuse non-atomic fallback')
    func=libc.renameat2
    func.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    func.restype=ctypes.c_int
    rc=func(AT_FDCWD,os.fsencode(source),AT_FDCWD,os.fsencode(target),RENAME_NOREPLACE)
    if rc!=0:
        errno=ctypes.get_errno()
        raise OSError(errno,os.strerror(errno),str(target))
    # Ensure rename directory metadata is durable where FS supports it.
    fd=os.open(str(target.parent),os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('Usage: atomic_publish.py SOURCE TARGET')
    publish(Path(sys.argv[1]),Path(sys.argv[2]))
