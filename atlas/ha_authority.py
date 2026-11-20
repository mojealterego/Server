"""Same-host coordinator exclusion and bounded standby promotion on local storage."""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import math
import os
from pathlib import Path
import stat
import time

class AuthorityBusy(ValueError):pass


def _validate(path,directory=False):
    st=path.lstat()
    kind=stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink==1
    if not kind or st.st_uid!=os.getuid() or st.st_mode&0o077:
        raise ValueError('Unsafe authority path: '+str(path))
    return st


@contextmanager
def authority(db,*,wait=0):
    if type(wait) not in (int,float) or not math.isfinite(wait) or not 0<=wait<=3600:
        raise ValueError('Standby wait must be 0..3600 seconds')
    db=Path(db);_validate(db.parent,True);db=db.parent.resolve()/db.name
    if db.exists() or db.is_symlink():_validate(db)
    path=db.parent/('.'+db.name+'.authority.lock')
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=_validate(path);got=os.fstat(fd)
        if (st.st_dev,st.st_ino)!=(got.st_dev,got.st_ino):raise ValueError('Authority lock replaced')
        end=time.monotonic()+wait
        while True:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError as exc:
                remaining=end-time.monotonic()
                if remaining<=0:raise AuthorityBusy('Coordinator already active') from exc
                time.sleep(min(.1,remaining))
        if db.exists() or db.is_symlink():_validate(db)
        current=_validate(path)
        if (current.st_dev,current.st_ino)!=(got.st_dev,got.st_ino):raise ValueError('Authority lock replaced')
        dfd=os.open(db.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        yield
    finally:os.close(fd)
